# RDPAudit 2.0 – Community-Edition

<!-- md-i18n:switcher -->
**In anderen Sprachen:** [English](README-EDITION.md) · Deutsch · [中文](README-EDITION.zh.md) · [हिन्दी](README-EDITION.hi.md) · [Español](README-EDITION.es.md) · [Русский](README-EDITION.ru.md)

Die kostenlose Edition: ein Windows-Server, lokale Erkennung und lokale Reaktion, kein Verbund und
keine Integrationen. Diese Edition muss aus sich heraus nützlich bleiben – ein einzelner Host mit
dem Dienst, dem Configurator und einer Sperre in der Windows-Firewall ist ein vollständiges Produkt.

Enthalten
---------
* Ereigniserfassung: Kanäle Security/RCM/LSM, hybride ETW-Aufnahme, Ringpuffer, WAL-Speicher.
* 21 Alarmregeln, Statistik der RDP-Aktivität, Sitzungskarte, Ansicht entfernter RDP-Clients.
* Durchsetzung der Windows-Firewall mit Whitelist, CIDR-Bereichen, Break-Glass-Whitelist und TTL.
* Ein MikroTik-Router mit RouterOS v7: Sperrregeln plus das schreibgeschützte Sicherheitsaudit (S-00..S-35).
* WinForms-Configurator (22 Registerkarten) und der Tray-Benachrichtiger.
* Lokale SQLite-/WAL-Datenbank mit Sharding, Aufbewahrung und Sicherung/Wiederherstellung.

Nicht enthalten (in Pro vorhanden)
----------------------------------
* Probelauf der Reaktion (`Firewall.ResponseDryRun`).
* Schreibgeschützte HTTPS-REST-API (`Api.Enabled`).
* SIEM-Export (CEF / LEEF 2.0 / NDJSON).
* Zabbix-Push-Kanal und seine Bereitstellungsbefehle.
* Host-übergreifende Korrelation.

Wird eine dieser Funktionen hier konfiguriert, startet der Dienst normal, schreibt pro Fähigkeit
genau eine ausdrückliche Warnung, die die Edition nennt, in der sie funktionieren würde, und tut
sonst nichts dafür. Er verweigert den Start nie: die lokale Erkennung wegen einer
Lizenzabweichung zu verlieren wäre schlimmer als die Abweichung selbst.

Build und Prüfung
-----------------
    dotnet build RdpAudit.sln -c Release -p:Platform=x64
    dotnet test  RdpAudit.sln -c Release --no-build -p:Platform=x64

Der Fenstertitel endet auf „- Community“, und `GetEditionInfo` (IPC 102) meldet, welche
Fähigkeiten diese Binärdatei enthält.
