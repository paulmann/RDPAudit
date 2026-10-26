# RDPAudit 2.0 – edición Community

<!-- md-i18n:switcher -->
**En otros idiomas:** [English](README-EDITION.md) · [Deutsch](README-EDITION.de.md) · [中文](README-EDITION.zh.md) · [हिन्दी](README-EDITION.hi.md) · Español · [Русский](README-EDITION.ru.md)

La edición gratuita: un servidor Windows, detección local y respuesta local, sin flota y sin
integraciones. Es la edición que debe seguir siendo útil por sí sola: un único host con el
servicio, el Configurator y un bloqueo en el Firewall de Windows ya es un producto completo.

Incluido
--------
* Recopilación de eventos: canales Security/RCM/LSM, ingesta ETW híbrida, búfer circular, almacén WAL.
* 21 reglas de alerta, estadísticas de actividad RDP, mapa de sesiones, vista de clientes RDP remotos.
* Aplicación del Firewall de Windows con lista blanca, rangos CIDR, lista blanca break-glass y TTL.
* Un router MikroTik con RouterOS v7: reglas de bloqueo y la auditoría de seguridad de solo lectura (S-00..S-35).
* Configurator de WinForms (22 pestañas) y el notificador de la bandeja del sistema.
* Base de datos local SQLite/WAL con sharding, retención y copia de seguridad/restauración.

No incluido (disponible en Pro)
-------------------------------
* Simulación de la respuesta (`Firewall.ResponseDryRun`).
* API REST HTTPS de solo lectura (`Api.Enabled`).
* Exportación a SIEM (CEF / LEEF 2.0 / NDJSON).
* Canal push de Zabbix y sus comandos de aprovisionamiento.
* Correlación entre hosts.

Si alguna de estas funciones se configura aquí, el servicio arranca con normalidad, registra una
advertencia explícita por capacidad indicando la edición en la que funcionaría y no hace nada al
respecto. Nunca se niega a arrancar: perder la detección local por un desajuste de licencia sería
peor que el desajuste.

Compilación y verificación
--------------------------
    dotnet build RdpAudit.sln -c Release -p:Platform=x64
    dotnet test  RdpAudit.sln -c Release --no-build -p:Platform=x64

El título de la ventana termina en "- Community", y `GetEditionInfo` (IPC 102) informa qué
capacidades contiene este binario.
