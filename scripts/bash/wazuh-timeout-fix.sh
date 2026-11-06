#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# wazuh-timeout-fix.sh
#
# Problem:  Auf langsamer Hardware (HDD) brauchen wazuh-indexer und
#           wazuh-manager beim Booten länger als das systemd-Start-Timeout.
#           systemd beendet sie dann mit SIGTERM (Exit-Status 143) -> "failed".
#
# Lösung:   systemd-Drop-in mit TimeoutStartSec=600. Die Original-Unit bleibt
#           unverändert (paketverwaltet) -> die Änderung übersteht Updates.
#
# Aufruf:   sudo bash wazuh-timeout-fix.sh
# Idempotent: kann beliebig oft ausgeführt werden.
# -----------------------------------------------------------------------------
set -euo pipefail

TIMEOUT="${TIMEOUT:-600}"
SERVICES=(wazuh-indexer wazuh-manager)

if [[ $EUID -ne 0 ]]; then
    echo "Bitte mit sudo ausführen." >&2
    exit 1
fi

for svc in "${SERVICES[@]}"; do
    dir="/etc/systemd/system/${svc}.service.d"
    file="${dir}/timeout.conf"
    mkdir -p "$dir"
    printf '[Service]\nTimeoutStartSec=%s\n' "$TIMEOUT" > "$file"
    echo "[+] ${file} -> TimeoutStartSec=${TIMEOUT}"
done

systemctl daemon-reload

for svc in "${SERVICES[@]}"; do
    echo "[*] ${svc}: $(systemctl show -p TimeoutStartUSec --value "$svc")"
    if ! systemctl is-active --quiet "$svc"; then
        echo "[*] Starte ${svc} ..."
        systemctl start "$svc"
    fi
done

echo
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat || true
echo
echo "[*] Lauschende Wazuh-Ports (1514 Events, 1515 Registrierung, 55000 API):"
ss -tlnp | grep -E ':(1514|1515|55000)\b' || echo "    (noch nicht alle Ports offen - Dienste starten noch)"
