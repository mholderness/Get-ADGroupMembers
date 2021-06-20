
<#PSScriptInfo

.VERSION 1.0
.GUID ffc2dd5e-5612-4605-ad74-3df6b249de78
.AUTHOR Mark Holderness
.PROJECTURI https://github.com/mholderness/Get-ADGroupMembers

#>

<# 

.DESCRIPTION 
 Get-ADGroupMembers supporting large groups.
 Returns ADObjects
 Avoids:
	msds-memberTransitive (limited in query results to 4500) and a subsequent call to AD to return AD object properties for each distinguishedName in the results.
	Get-ADGroupMember -Recursive (default Active Directory Web Services MaxGroupOrMemberEntries limit of 5000) ... and a subsequent call to Get-ADObject if the ADPrincipal object properties are not sufficient.
	LDAP_MATCHING_RULE_IN_CHAIN (which has none of the shortcomings of the above approaches but) can be very slow.

.SYNOPSIS
 Get-ADGroupMembers supporting large groups (< 5000)
.OUTPUTS
 ADObject https://docs.microsoft.com/en-us/dotnet/api/microsoft.activedirectory.management.adobject?view=activedirectory-management-10.0
.EXAMPLE
 $DirectMembersOfBigGroup = Get-ADGroupMembers 'BigGroup' -Verbose
.EXAMPLE
 $IndirectMembersOfBigGroup = Get-ADGroupMembers 'BigGroup' -Indirect -Verbose
.EXAMPLE
 $RecursiveMembersOfBigGroup = Get-ADGroup 'BigGroup' | Get-ADGroupMembers -Recursive -Verbose
#>
[cmdletbinding(DefaultParameterSetName="GetDirectMember")]
Param(
	<#	Specifies an Active Directory group object.  See the requirements of the Identity parameter of Get-ADGroup for more information:
			'Get-Help -Name Get-ADGroup -Parameter Identity'
	#>
	[Parameter(Mandatory,Position=0,ValueFromPipeline)]$Identity,
	<#	Specifies whether to include ADObjects with objectClass -eq group.  Groups are not returned by default.
	#>
	[switch]$IncludeGroups,
	<#	Specifies to get all members in the hierarchy of a group that do not contain child objects.
	#>
	[Parameter(ParameterSetName='GetRecursiveMember')][switch]$Recursive,
	<#	Specifies to get all indirect members in the hierarchy of a group that do not contain child objects.  In other words, return all members of directly nested groups of a group.
	#>
	[Parameter(ParameterSetName='GetIndirectMember')][switch]$Indirect,
	<#	Specifies the properties to return for each group member.
	#>
	[string[]]$MemberProperties = @("distinguishedName","name","objectClass")
)
Begin {
	#Hash Table used by the Get-ADObjectMemberOfGroup inner function to avoid infinite recursion.
	$ADGroupProcessed = @{}
	#Hash Table used by the Get-ADObjectMemberOfGroup inner function to avoid returning duplicate objects.
	$ADGroupMemberSeen = @{}
	#Hash Table used to splat parameters on calls to the Get-ADObjectMemberOfGroup inner function.
	$GetADObjectMemberOfGroup = @{}
	$GetADObjectMemberOfGroup.MemberProperties = $MemberProperties
	If($IncludeGroups) {
		$GetADObjectMemberOfGroup.IncludeGroups = $IncludeGroups
	}
	Function Get-ADObjectMemberOfGroup
	{	
		[cmdletbinding()]
		Param(
			[Parameter(Mandatory,Position=0,ValueFromPipeline)]$Identity,
			[string[]]$MemberProperties = @("distinguishedName","name","objectClass"),
			[switch]$Recursive,
			[switch]$IncludeGroups
		)
		Begin {
			If($Recursive) {
				If(!$ADGroupProcessed){
					Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : Create ADGroupsProcessed hash table to track process group to avoid infinite recursion."
					$ADGroupProcessed = @{}
				}
				If(!$ADGroupMemberSeen){
					Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : Create ADGroupMembersSeen hash table to avoid returning duplicate members."
					$ADGroupMemberSeen = @{}
				}
				If(-Not $MemberProperties -Contains "objectClass"){
					#objectClass required to trigger recursive function calls for member groups.
					$MemberProperties += "objectClass"
				}
				$GetADObjectMemberOfGroupSplat = @{}
				$GetADObjectMemberOfGroupSplat.MemberProperties = $MemberProperties
				If($IncludeGroups) {
					$GetADObjectMemberOfGroup.IncludeGroups = $IncludeGroups
				}
			}
			$GetADObjectSplat = @{}
			$GetADObjectSplat.Properties = $MemberProperties
		}
		Process {
			ForEach($Group in $Identity){
				Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : $Group"
				[array]$ADGroup = Get-ADGroup $Group
				If($ADGroup.Count -eq 1) {
					$ADGroupIdentity = $ADGroup.distinguishedName
					If($ADGroupProcessed.ContainsKey($ADGroupIdentity)) {
						Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : Skipping group to avoid infinite recursion: $($ADGroup.distinguishedName)"
					}
					Else {
						$ADGroupProcessed.Add($ADGroupIdentity,"")
						If($Recursive) {
							$Member = Get-ADObject -LDAPFilter "(&(memberOf=$($ADGroup.distinguishedName)))" @GetADObjectSplat
							#Return members that are not groups and haven't previously been returned (where an object is a member of more than one group in the hierarchy)
							$Member | ForEach-Object {
								If($ADGroupMemberSeen.ContainsKey($PSItem.distinguishedName)) {
									Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : Skipping ADObject to avoid returning duplicates: $($PSItem.distinguishedName)"
								}
								Else {
									$ADGroupMemberSeen.Add($PSItem.distinguishedName,"")
									If($PSItem.objectClass -eq 'group' -And -Not $IncludeGroups) {
										Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : Skipping ADObject.  objectClass -eq group and IncludeGroups -eq $IncludeGroups : $($PSItem.distinguishedName)"
									}
									Else {
										$PSItem
									}
								}
							}
							[array]$MemberGroup = $Member | Where-Object { $PSItem.objectClass -eq 'group' }
							If($MemberGroup.Count -ge 1){
								Get-ADObjectMemberOfGroup $MemberGroup @GetADObjectMemberOfGroupSplat -Recursive
							}
						}
						Else {
							If($IncludeGroups) {
								Get-ADObject -LDAPFilter "(&(memberOf=$($ADGroup.distinguishedName)))" @GetADObjectSplat
							}
							Else {
								Get-ADObject -LDAPFilter "(&(memberOf=$($ADGroup.distinguishedName))(!(objectClass=group)))" @GetADObjectSplat
							}
						}
					}
				}
			}
		}
	}
}
Process {
	ForEach($Group in $Identity){
		Write-Verbose "$(Get-Date) | Get-ADGroupMembers : $Group"
		[array]$ADGroup = Get-ADGroup $Group
		If($ADGroup.Count -eq 1) {
			If($Indirect) {
				Write-Verbose "$(Get-Date) | Get-ADGroupMembers : $($ADGroup.Name) : Indirect : Searching for direct members with objectClass -eq group and returning transitive members of each."
				[array]$MemberGroup = Get-ADObject -LDAPFilter "(&(memberOf=$($ADGroup.distinguishedName))(objectClass=group))"
				If($MemberGroup.Count -ge 1) {
					Get-ADObjectMemberOfGroup $MemberGroup @GetADObjectMemberOfGroup -Recursive
				}
			}
			ElseIf($Recursive) {
				Write-Verbose "$(Get-Date) | Get-ADGroupMembers : $($ADGroup.Name) : Recursive : Searching for transitive members."  
				Get-ADObjectMemberOfGroup $ADGroup.distinguishedName @GetADObjectMemberOfGroup -Recursive
			}
			Else {
				Write-Verbose "$(Get-Date) | Get-ADGroupMembers : $($ADGroup.Name) : Searching for direct members."  
				Get-ADObjectMemberOfGroup $ADGroup.distinguishedName @GetADObjectMemberOfGroup
			}
		}
		Else {
			Write-Warning "$(Get-Date) | Get-ADGroup $Group returned none or more than one."
		}
	}
}