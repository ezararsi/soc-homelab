# Probleme & Lösungen

Dieses Dokument hält die beim Aufbau aufgetretenen Probleme fest, jeweils mit Diagnose, Lösung und Erkenntnis. Aufbau der Umgebung: siehe [`ARCHITEKTUR.md`](ARCHITEKTUR.md).

Jeder Eintrag in Teil A ist gleich aufgebaut: Problem, Diagnose, Lösung, Erkenntnis.

---

## Zusammenfassung

Die Liste umfasst rund 30 Probleme aus den Bereichen Host, VirtualBox, Firewall, Active Directory, Linux und Wazuh. Die meisten gingen auf knappe Ressourcen (HDD, RAM, CPU) zurück oder auf Dienste, die zu langsam oder in der falschen Reihenfolge starteten. Kleinere Bedienprobleme habe ich hier weggelassen.

---

## Teil A: Ausgewählte Fälle im Detail

### A1. Defekte Leseverbindung zur Lab-Festplatte (Event-ID 51)

| | |
|---|---|
| **Problem** | Die Prüfsumme einer ISO ließ sich nicht berechnen: „A device which does not exist was specified.“ |
| **Diagnose** | Volume und Datenträger meldeten „Healthy“. Ein Kopierversuch scheiterte gleich. Im System-Ereignisprotokoll (`Get-WinEvent`) fand sich mehrfach **Event-ID 51** (Paging-Fehler) auf genau diesem USB-Datenträger. |
| **Lösung** | Anschluss an einen hinteren USB-3.0-Port direkt am Mainboard → Datei lesbar, SHA256 stimmt mit dem offiziellen Wert überein. |
| **Erkenntnis** | Der Status „Healthy“ schließt Fehler nicht aus. Den entscheidenden Hinweis lieferte das Ereignisprotokoll. |

### A2. Langsame Downloads trotz schneller Leitung

| | |
|---|---|
| **Problem** | ISO-Downloads mit nur ~2 MB/s. |
| **Diagnose** | Netzwerkadapter mit 1 Gbit/s verbunden, kein VPN aktiv; Speedtest ~290 Mbit/s → der Engpass lag bei der **einzelnen TCP-Verbindung** zum Server. |
| **Lösung** | Download-Manager `aria2c -x 16 -s 16` (16 parallele Segmente über HTTP-Range-Requests) → Ø 30 MiB/s, ca. 15× schneller. |
| **Erkenntnis** | Erst messen, wo der Engpass liegt (Adapter, Leitung, Gegenstelle), dann gezielt optimieren. |

### A3. Firewall-Regel ohne Wirkung – Port auf der falschen Seite

| | |
|---|---|
| **Problem** | Nach Anlegen einer Erlaubnisregel für HTTPS blieb die Web-GUI der Firewall unerreichbar. |
| **Diagnose** | Statt der Oberfläche die **tatsächlich geladene Regel** geprüft: `pfctl -sr \| grep 10.10.20.1` → `from 10.10.20.1 port = https`. Port 443 war als **Quell-Port** eingetragen. Clients verwenden aber zufällige Quell-Ports (49152–65535). |
| **Lösung** | Quell-Port auf „any“, Ziel-Port auf HTTPS. Danach Positivtest (Web-GUI lädt) **und** Negativtest (Ping weiterhin blockiert). |
| **Erkenntnis** | Konfiguration im laufenden System verifizieren, nicht nur in der Oberfläche. Immer positiv und negativ testen. |

### A4. Default Deny nachgewiesen per Gegenprobe

| | |
|---|---|
| **Problem** | Ping vom Admin-PC zur Firewall: 100 % Paketverlust. |
| **Diagnose** | Hypothese: keine Regel auf dem neuen Interface → Default Deny. Gegenprobe: Paketfilter kurz deaktiviert (`pfctl -d`) → Ping funktioniert sofort. |
| **Lösung** | Filter wieder aktiviert, nur die benötigte Verbindung gezielt erlaubt (Least Privilege). |
| **Erkenntnis** | Eine Variable ändern, Wirkung beobachten → eindeutige Ursache. Sicherheitsfunktionen nur kurz und kontrolliert abschalten. |

### A5. Rule Shadowing – Segmentierung unbemerkt ausgehebelt

| | |
|---|---|
| **Problem** | Eine neue Regel „LAN darf nur die Agentenports des SIEM erreichen“ hatte keine Wirkung. |
| **Diagnose** | Die Standardregel „LAN → any“ stand **davor**. Bei First Match greift die breite Regel zuerst – das LAN hätte Dashboard, SSH und API des SIEM erreicht. |
| **Lösung** | Standardregel geändert auf „LAN → alles **außer** SOC-Netz“ (Invert Destination). Ergebnis-Matrix getestet. |
| **Erkenntnis** | Regelreihenfolge ist sicherheitsrelevant. Ohne gezielten Test bleibt ein solcher Fehler unbemerkt. |

### A6. SIEM-Dienste starten nach Neustart nicht (systemd-Timeout)

| | |
|---|---|
| **Problem** | Agent konnte Port 1515 nicht erreichen; nach dem Boot waren `wazuh-manager` und `wazuh-indexer` im Zustand **failed**. |
| **Diagnose** | Zuerst ausgeschlossen, dass die Firewall schuld ist (Test vom Host im selben Netz ebenfalls Timeout; VM-Screenshot zeigte noch laufenden Bootvorgang). Danach `systemctl status`: „start operation timed out“, Exit-Status **143** (= SIGTERM durch systemd). Der Dienst arbeitete, war auf der HDD nur zu langsam. |
| **Lösung** | Update-sicheres **systemd-Drop-in** mit `TimeoutStartSec=600` für Indexer und Manager, `daemon-reload`, Kontrolle der Ports mit `ss -tlnp`. |
| **Erkenntnis** | Zuerst prüfen, ob das Zielsystem läuft, bevor die Firewall verändert wird. Drop-ins verwenden statt die Original-Unit zu bearbeiten. |

### A7. Wazuh-Agent-Installation hängt im Hintergrund

| | |
|---|---|
| **Problem** | Nach `msiexec` meldete `NET START WazuhSvc` „The service name is invalid“. |
| **Diagnose** | `msiexec` kehrt sofort zurück, die Installation lief im Hintergrund weiter. Im Application-Log nur **Event 1040** (Transaktion begonnen), kein 11707/11708 (Erfolg/Fehler) → Installation hing. |
| **Lösung** | Hängende Prozesse beendet; Installation mit `Start-Process … -Wait`, `/qn` und ausführlichem Protokoll `/l*v` wiederholt → Dienst läuft. |
| **Erkenntnis** | Bei Software-Verteilung auf das Ende der Installation warten und immer ein Installationsprotokoll schreiben. |

### A8. Dashboard „No API available“ bei laufenden Diensten

| | |
|---|---|
| **Problem** | Wazuh-Dashboard meldete Timeouts, obwohl alle Dienste aktiv waren. |
| **Diagnose** | `ss -tlnp` → API lauscht. `api.log` → Anfragen brauchten ~20 s. `top` → Load Average 12,8 bei 2 CPUs (Lastspitze nach Dienst-Neustarts und erster Schwachstellen-Datenbank). `free -h` → genug RAM verfügbar. |
| **Lösung** | Last abklingen lassen, Seite neu laden. |
| **Erkenntnis** | Logs und Kennzahlen lesen statt raten. Load Average immer im Verhältnis zur CPU-Anzahl bewerten. |

### A9. Domänenbeitritt: halb erfolgreich

| | |
|---|---|
| **Problem** | `Add-Computer` mit gleichzeitiger Umbenennung lieferte eine rote Fehlermeldung. |
| **Diagnose** | Genau gelesen: Beitritt **erfolgreich**, nur die Umbenennung scheiterte („The directory service is busy“ – zweite Änderung direkt nach Kontoanlage). |
| **Lösung** | `Rename-Computer … -DomainCredential` (benennt auch das AD-Objekt um); Ergebnis mit `Get-ADComputer` auf dem DC verifiziert. |
| **Erkenntnis** | Fehlermeldungen vollständig lesen: Eine Fehlermeldung bedeutet nicht, dass der gesamte Vorgang fehlgeschlagen ist. |

### A10. DHCP-Konfiguration erst am Client als fehlerhaft erkannt

| | |
|---|---|
| **Problem** | Der Client erhielt ein falsches DNS-Suffix. |
| **Diagnose** | `ipconfig /all` am Client zeigte den Fehler; Ursache war ein Tippfehler in DHCP-Option 15 auf dem Server. |
| **Lösung** | Option korrigiert, `ipconfig /renew` am Client, Optionen 3/6/15/51 kontrolliert. |
| **Erkenntnis** | Konfiguration am Ergebnis beim Empfänger prüfen, nicht nur am Server. |

---

## Teil B: Alle Probleme im Überblick

### B1. Host & Hardware

| Problem | Diagnose | Lösung |
|---|---|---|
| Virtualisierung im Task-Manager „Disabled“ | CPU kann AMD-V, im BIOS aus | SVM Mode im UEFI aktiviert; Neustart in die Firmware mit `shutdown /r /fw /t 0` (Admin-Rechte nötig, sonst Fehler 1314) |
| ISO nicht lesbar | Event-ID 51 auf USB-Datenträger | Port gewechselt (siehe A1) |
| Downloads ~2 MB/s | Drosselung pro Verbindung | `aria2c` mit 16 Verbindungen (siehe A2) |
| Installationen extrem langsam | Task-Manager: Datenträger 93 % aktiv bei ~1 MB/s → HDD-Engpass bei Random I/O; beim Entpacken CPU ~100 % | Hintergrundprogramme schließen, Energiesparplan „Höchstleistung“, Defender-Ausnahme für VM-Ordner, Host-I/O-Cache; langfristig SSD |

### B2. Virtualisierung (VirtualBox)

| Problem | Diagnose | Lösung |
|---|---|---|
| Netzwerk-Manager in neuer GUI nicht auffindbar | Menü umgebaut | Host-only-Netz per `VBoxManage` konfiguriert |
| `modifyvm` → „not mutable (Saved)“ | VM im gespeicherten Zustand | `discardstate` |
| Nach Installation startet wieder das Setup | ISO noch eingelegt, Boot-Reihenfolge DVD vor Platte | Laufwerk leeren (`--medium emptydrive`), mit `showvminfo \| Select-String "iso"` verifiziert |
| VM-Fenster „Keine Rückmeldung“ | Status `running`, ACPI-Shutdown funktioniert → nur das **Anzeigefenster** hing | Fenster beenden; künftig Start mit `--type separate` |
| Eingaben in Konsole ohne Zwischenablage | keine Guest Additions | Text per `keyboardputstring` / `keyboardputscancode` vom Host senden |
| Windows-Setup reagiert nicht | `screenshotpng` unverändert, Eingaben per Scancode wirkungslos, Disk/CPU idle | Reset → klassisches Setup („Previous Version of Setup“) |
| Windows-11-Setup: „This PC can't run Windows 11“ | RAM < 4 GB, Secure Boot aus, CPU nicht gelistet | Laborschalter `LabConfig` per Registry im Setup (dokumentierte Lab-Abweichung) |
| Ersteinrichtung hängt (schwarz / „This might take a few minutes“) | keine Plattenaktivität; Windows wartet offline auf Online-Dienste | Reset, Einrichtung setzt fort |

### B3. Firewall (OPNsense)

| Problem | Diagnose | Lösung |
|---|---|---|
| Installer-Warnung: zu wenig RAM | Live-System läuft im RAM | RAM temporär auf 3 GB, danach zurück auf 1 GB |
| Interfaces nach Installation falsch zugewiesen | Live-Zuweisung nicht übernommen | Zuweisung im installierten System wiederholt, gegen Plan geprüft |
| Ping blockiert | Default Deny | Gegenprobe `pfctl -d` (siehe A4) |
| Web-GUI trotz Regel blockiert | Port als Quell-Port eingetragen | korrigiert (siehe A3) |
| Ports 1514/1515 im Regel-Editor nicht eingebbar | neue GUI bietet nur benannte Dienste | **Port-Alias** `Wazuh_Agent` |
| LAN erreicht das ganze SOC-Netz | Rule Shadowing | Standardregel invertiert (siehe A5) |

### B4. Active Directory & Windows Server

| Problem | Diagnose | Lösung |
|---|---|---|
| Schwarzer Bildschirm nach Umbenennung | VM hing beim Neustart, keine Plattenaktivität | Reset, Name verifiziert |
| Domäne mit abweichendem DNS-Namen angelegt | `Get-ADDomain` zeigte die Abweichung | DC herabgestuft, Forest neu angelegt – diesmal mit Werten in Variablen und Kontrollausgabe **vor** der Ausführung |
| Test-Anmeldung lieferte Status 0xC0000224 | Passwortwechsel bei Erstanmeldung erzwungen | korrekt interpretiert; trotzdem gültiger Nachweis für Event 4625 |
| Falsches DNS-Suffix am Client | DHCP-Option 15 | korrigiert (siehe A10) |
| Abweichende Zeitzone am DC | Standard Pacific Time | `Set-TimeZone` – konsistente Zeitstempel für die SIEM-Korrelation |
| Umbenennung beim Domänenbeitritt gescheitert | „directory service is busy“ | `Rename-Computer -DomainCredential` (siehe A9) |
| DC hängt im Betrieb | VM-Screenshot | ACPI, dann Reset; **Shutdown Event Tracker** ausgefüllt (Events 6008/1076) |
| DC hängt beim Herunterfahren („Shutting down service: DHCP Server“) | keine Fortschritte | Ausschalten; beim nächsten Start AD-Dienste geprüft; Snapshot als Rückfallebene |

### B5. Linux (Ubuntu / WAZUH01)

| Problem | Diagnose | Lösung |
|---|---|---|
| Installer ohne Internet | SOC-Netz hatte noch keine Regeln | Installation von der ISO, Regeln danach |
| Nur ~28 GB von 60 GB nutzbar | Standard-LVM-Layout | Logical Volume im Installer auf volle Größe erweitert |
| DNS-Auflösung hängt | Firewall-Live-Log zeigte „pass“; `dig @10.10.10.10` Timeout | DC01 lief nicht → gestartet |
| Passwort versehentlich ins Benutzernamenfeld der Konsole eingegeben | Klartext sichtbar und in `auth.log` protokolliert | als kompromittiert behandelt, sofort mit `passwd` geändert |

### B6. SIEM & Agenten

| Problem | Diagnose | Lösung |
|---|---|---|
| Dashboard-Timeouts | Load Average 12,8 | abwarten (siehe A8) |
| Port 1515 nicht erreichbar | WAZUH01 noch im Boot, danach Dienste „failed“ | Bootzeit abwarten; systemd-Timeout erhöht (siehe A6) |
| Agent-Dienst nach Installation unbekannt | MSI-Transaktion hing | Neuinstallation mit `-Wait` und Protokoll (siehe A7) |
| Agenten-Log nicht am erwarteten Ort | Installationspfad abweichend | Dienstpfad per `Get-CimInstance Win32_Service` ermittelt |
| `Restart-Service` scheitert | Stopp überschreitet Zeitgrenze | Prozess beenden, Dienst starten |
| Ereignisse vor Inbetriebnahme fehlen im SIEM | SIEM sieht nur, was nach dem Ausrollen passiert | Erkenntnis: SIEM als Erstes ausrollen |
| Eigene Admin-Arbeit erzeugt ATT&CK-Alarme | Downloads, PowerShell, neue Dienste | Erkenntnis: Kontext (wer, wann, angekündigte Änderung?) entscheidet über die Bewertung |

---

## Teil C: Fazit

Rückblickend stand die Ursache fast immer in einem Log: Ereignisprotokoll, `systemctl status`, `api.log` oder das Live-Log der Firewall. Geholfen hat vor allem, eine Verbindung Station für Station zu prüfen (Quelle, Firewall, Ziel) und dabei unten anzufangen, also zuerst zu klären, ob das Zielsystem überhaupt läuft. Der Oberfläche habe ich nach dem Fehler mit der Firewall-Regel (A3) weniger vertraut und stattdessen den tatsächlichen Zustand abgefragt (`pfctl -sr`, `auditpol`, `Get-ADDomain`, `ss -tlnp`).

Vor größeren Änderungen lege ich inzwischen einen Snapshot an und lasse mir die Werte vorher ausgeben. Das hätte mir beim Neuaufsetzen der Domäne einiges an Zeit gespart.
