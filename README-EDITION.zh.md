# RDPAudit 2.0 - Community 版

<!-- md-i18n:switcher -->
**其他语言：** [English](README-EDITION.md) · [Deutsch](README-EDITION.de.md) · 中文 · [हिन्दी](README-EDITION.hi.md) · [Español](README-EDITION.es.md) · [Русский](README-EDITION.ru.md)

免费版：一台 Windows 服务器，本地检测与本地响应，没有主机集群，也没有外部集成。这个版本必须
能够独立使用——一台主机上运行服务、Configurator 和一条 Windows 防火墙阻止规则，就已经是一个
完整的产品。

包含内容
--------
* 事件采集：Security/RCM/LSM 通道、混合 ETW 摄入、环形缓冲区、WAL 存储。
* 21 条告警规则、RDP 活动统计、会话地图、远程 RDP 客户端视图。
* Windows 防火墙强制执行，支持白名单、CIDR 网段、应急白名单（break-glass）和 TTL。
* 一台 MikroTik RouterOS v7 路由器：阻止规则以及只读安全审计（S-00..S-35）。
* WinForms Configurator（22 个选项卡）和托盘通知程序。
* 本地 SQLite/WAL 数据库，支持分片、保留策略和备份/恢复。

不包含的内容（Pro 版提供）
--------------------------
* 响应演练（`Firewall.ResponseDryRun`）。
* 只读 HTTPS REST API（`Api.Enabled`）。
* SIEM 导出（CEF / LEEF 2.0 / NDJSON）。
* Zabbix 推送通道及其预置命令。
* 跨主机关联。

如果在此处配置了上述任何一项，服务仍会正常启动，为每项能力记录一条明确的警告，指出可以在哪个
版本中生效，并且不对该能力做任何处理。服务绝不会拒绝启动：因为授权不匹配而丢失本地检测，比
不匹配本身更糟。

构建与验证
----------
    dotnet build RdpAudit.sln -c Release -p:Platform=x64
    dotnet test  RdpAudit.sln -c Release --no-build -p:Platform=x64

窗口标题以 "- Community" 结尾，`GetEditionInfo`（IPC 102）会报告此二进制文件包含哪些能力。
