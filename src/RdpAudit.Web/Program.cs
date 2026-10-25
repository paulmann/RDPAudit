// File:    src/RdpAudit.Web/Program.cs
// Module:  RdpAudit.Web (entry point)
// Purpose: Entry point of the IIS-hosted web-UI proxy. Production hosting is delegated to
//          WebUiProxyApp.RunAsync: it builds the pipeline, fails fast when the shared bearer
//          token cannot be read from the vault, then blocks serving requests (IIS in-process).
//          Keeping Program.cs as a thin wrapper lets the integration tests exercise the exact
//          same pipeline through WebUiProxyApp.Build on a TestServer.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Web.Hosting;

await WebUiProxyApp.RunAsync(args);
