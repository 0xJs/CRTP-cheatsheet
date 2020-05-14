# Red-team-cheatsheet

# Summary

# Domain Enumeration
## Powerview General
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

#### 
```

```

#### 
```

```

#### 
```

```

