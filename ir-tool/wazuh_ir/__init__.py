"""wazuh_ir - Incident-Response-Tool für das SOC-Lab.

Fragt Alarme aus dem Wazuh-Indexer ab, wertet sie aus (Schweregrad, betroffene
Systeme, MITRE ATT&CK, Zeitverlauf) und erstellt einen Incident-Report nach der
Struktur von NIST SP 800-61.
"""

__version__ = "1.0.0"
