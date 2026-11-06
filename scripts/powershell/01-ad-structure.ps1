# 01-ad-structure.ps1
# Legt die OU-Struktur und Abteilungsgruppen fuer die Domaene soclab.internal an.
# Ausfuehren auf DC01 als Domain Admin.

$DomainDN = (Get-ADDomain).DistinguishedName      # z. B. DC=soclab,DC=internal
$RootOU   = "SOCLAB"
$RootDN   = "OU=$RootOU,$DomainDN"

# Funktion: OU nur anlegen, wenn sie noch nicht existiert (idempotent)
function New-OUIfMissing {
    param([string]$Name, [string]$Path)
    $dn = "OU=$Name,$Path"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true
        Write-Host "[+] OU angelegt: $dn" -ForegroundColor Green
    } else {
        Write-Host "[=] OU existiert bereits: $dn" -ForegroundColor Yellow
    }
}

# 1) Firmen-OU
New-OUIfMissing -Name $RootOU -Path $DomainDN

# 2) Unter-OUs
$SubOUs = @("Users", "Computers", "Servers", "Groups", "Admins", "ServiceAccounts")
foreach ($ou in $SubOUs) { New-OUIfMissing -Name $ou -Path $RootDN }

# 3) Abteilungs-OUs unter Users
$Departments = @("IT", "HR", "Finance", "Sales")
foreach ($dep in $Departments) { New-OUIfMissing -Name $dep -Path "OU=Users,$RootDN" }

# 4) Sicherheitsgruppen pro Abteilung (GG = Global Group)
$GroupPath = "OU=Groups,$RootDN"
foreach ($dep in $Departments) {
    $grp = "GG_$dep"
    if (-not (Get-ADGroup -Filter "Name -eq '$grp'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $grp -GroupScope Global -GroupCategory Security -Path $GroupPath -Description "Mitarbeiter Abteilung $dep"
        Write-Host "[+] Gruppe angelegt: $grp" -ForegroundColor Green
    } else {
        Write-Host "[=] Gruppe existiert bereits: $grp" -ForegroundColor Yellow
    }
}

Write-Host "`nFertig. Struktur:" -ForegroundColor Cyan
Get-ADOrganizationalUnit -Filter * -SearchBase $RootDN | Select-Object -ExpandProperty DistinguishedName