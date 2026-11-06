# 03-ad-admin.ps1
# Legt ein separates, privilegiertes Admin-Konto an (Trennung von Alltags- und Admin-Konto).

$DomainDN  = (Get-ADDomain).DistinguishedName
$UPNSuffix = (Get-ADDomain).DNSRoot
$AdminPath = "OU=Admins,OU=SOCLAB,$DomainDN"
$sam       = "adm.anna.huber"

if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
    $pw = Read-Host "Passwort fuer $sam" -AsSecureString
    New-ADUser -Name "ADM Anna Huber" -GivenName "Anna" -Surname "Huber" `
        -SamAccountName $sam -UserPrincipalName "$sam@$UPNSuffix" `
        -Description "Privilegiertes Admin-Konto von anna.huber - nur fuer Administration" `
        -Path $AdminPath -AccountPassword $pw -Enabled $true
    Add-ADGroupMember -Identity "Domain Admins" -Members $sam
    Write-Host "[+] $sam angelegt und zu Domain Admins hinzugefuegt" -ForegroundColor Green
} else {
    Write-Host "[=] $sam existiert bereits" -ForegroundColor Yellow
}

Write-Host "`nMitglieder von Domain Admins:" -ForegroundColor Cyan
Get-ADGroupMember "Domain Admins" | Select-Object SamAccountName, ObjectClass