# 02-ad-users.ps1
# Legt Mitarbeiter-Konten in den Abteilungs-OUs an und fuegt sie ihrer Gruppe hinzu.
# Ausfuehren auf DC01 als Domain Admin, nach 01-ad-structure.ps1.

$DomainDN  = (Get-ADDomain).DistinguishedName
$UPNSuffix = (Get-ADDomain).DNSRoot              # soclab.internal
$RootDN    = "OU=SOCLAB,$DomainDN"

# Benutzerliste im CSV-Format (in Produktion: Import-Csv aus einer Datei/HR-System)
$Users = @"
FirstName,LastName,Department,Title
Anna,Huber,IT,Systemadministratorin
Lukas,Gruber,IT,Helpdesk
Sophie,Wagner,HR,HR-Managerin
David,Bauer,HR,Recruiter
Laura,Pichler,Finance,Buchhalterin
Felix,Steiner,Finance,Controller
Marie,Moser,Sales,Vertrieb
Jonas,Mayer,Sales,Key Account Manager
"@ | ConvertFrom-Csv

# Passwort wird zur Laufzeit abgefragt -> steht NIE im Skript/Repo
$InitialPassword = Read-Host "Initial-Passwort fuer alle neuen Benutzer" -AsSecureString

foreach ($u in $Users) {
    $sam  = ("{0}.{1}" -f $u.FirstName, $u.LastName).ToLower()    # anna.huber
    $path = "OU=$($u.Department),OU=Users,$RootDN"

    if (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        Write-Host "[=] Benutzer existiert bereits: $sam" -ForegroundColor Yellow
        continue
    }

    New-ADUser -Name "$($u.FirstName) $($u.LastName)" `
        -GivenName $u.FirstName -Surname $u.LastName `
        -SamAccountName $sam -UserPrincipalName "$sam@$UPNSuffix" `
        -Department $u.Department -Title $u.Title `
        -Path $path -AccountPassword $InitialPassword `
        -ChangePasswordAtLogon $true -Enabled $true

    Add-ADGroupMember -Identity "GG_$($u.Department)" -Members $sam
    Write-Host "[+] $sam angelegt -> OU $($u.Department), Gruppe GG_$($u.Department)" -ForegroundColor Green
}

Write-Host "`nUebersicht:" -ForegroundColor Cyan
Get-ADUser -Filter * -SearchBase "OU=Users,$RootDN" -Properties Department, Title |
    Select-Object SamAccountName, Department, Title | Format-Table -AutoSize