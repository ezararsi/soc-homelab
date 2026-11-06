# 00-create-vms.ps1
# Erstellt die VMs FW01-OPNsense, DC01 und CLIENT01 in VirtualBox (ohne Betriebssystem-Installation).
# Ausfuehren auf dem Host. Voraussetzung: ISOs in $IsoDir, Host-only-Adapter 10.10.20.1/24 konfiguriert.

$VBox   = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$VmDir  = "E:\SOC-Lab\VMs"
$IsoDir = "E:\SOC-Lab\ISOs"

function New-LabVM {
    param(
        [string]$Name, [string]$OsType, [int]$RamMB, [int]$Cpus,
        [int]$DiskMB, [string]$Iso, [string[]]$ExtraArgs
    )
    # Idempotenz: existiert die VM schon, wird sie uebersprungen
    if (& $VBox list vms | Select-String "`"$Name`"") {
        Write-Host "[=] VM existiert bereits: $Name" -ForegroundColor Yellow
        return
    }
    $vdi = "$VmDir\$Name\$Name.vdi"
    & $VBox createvm --name $Name --ostype $OsType --register
    & $VBox modifyvm $Name --memory $RamMB --cpus $Cpus @ExtraArgs
    & $VBox createmedium disk --filename $vdi --size $DiskMB
    & $VBox storagectl $Name --name SATA --add sata --controller IntelAhci
    & $VBox storageattach $Name --storagectl SATA --port 0 --device 0 --type hdd --medium $vdi
    & $VBox storageattach $Name --storagectl SATA --port 1 --device 0 --type dvddrive --medium "$IsoDir\$Iso"
    Write-Host "[+] VM angelegt: $Name" -ForegroundColor Green
}

# Firewall: WAN (NAT), LAN-CORP (intern), SOC-MGMT (Host-only)
New-LabVM -Name "FW01-OPNsense" -OsType "FreeBSD_64" -RamMB 1024 -Cpus 1 -DiskMB 20480 `
    -Iso "OPNsense-26.7-dvd-amd64.iso" `
    -ExtraArgs @("--nic1","nat","--nic2","intnet","--intnet2","LAN-CORP",
                 "--nic3","hostonly","--hostonlyadapter3","VirtualBox Host-Only Ethernet Adapter")

# Domain Controller: nur LAN-CORP, UEFI
New-LabVM -Name "DC01" -OsType "Windows2022_64" -RamMB 2560 -Cpus 2 -DiskMB 61440 `
    -Iso "WindowsServer2025.iso" `
    -ExtraArgs @("--firmware","efi","--nic1","intnet","--intnet1","LAN-CORP",
                 "--vram","128","--graphicscontroller","vboxsvga")

# Client: nur LAN-CORP, UEFI + TPM 2.0 (Windows 11); Installation mit 4096 MB empfohlen
New-LabVM -Name "CLIENT01" -OsType "Windows11_64" -RamMB 3072 -Cpus 2 -DiskMB 65536 `
    -Iso "Windows11_LTSC.iso" `
    -ExtraArgs @("--firmware","efi","--tpm-type","2.0","--nic1","intnet","--intnet1","LAN-CORP",
                 "--vram","128","--graphicscontroller","vboxsvga","--clipboard-mode","bidirectional")