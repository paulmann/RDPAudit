/*
 * File   : Program.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik)
 * Purpose: WinForms entry point for the MikroTik setup wizard. Configures high-DPI rendering, builds
 *          a console-or-debug logger factory (so the wizard can be debugged like the Service), and
 *          launches the MainForm. The wizard runs elevated (see app.manifest) because it writes to the
 *          machine Trusted Root certificate store and creates router-side firewall objects.
 * Depends: System.Windows.Forms.Application, Microsoft.Extensions.Logging, MainForm
 * Extends: To inject a different logging sink or a real DI container, build it here and hand the
 *          resulting ILoggerFactory (and any services) to MainForm.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Windows.Forms;
using Microsoft.Extensions.Logging;
using RdpAudit.Mikrotik.Ui;

namespace RdpAudit.Mikrotik;

/// <summary>WinForms entry point for the MikroTik setup wizard.</summary>
internal static class Program
{
	// ── Public API ───────────────────────────────────────────────────────────────

	[STAThread]
	private static void Main()
	{
		ApplicationConfiguration.Initialize();

		using ILoggerFactory loggerFactory = LoggerFactory.Create(builder =>
		{
			builder.AddSimpleConsole(options => options.SingleLine = true);
			builder.SetMinimumLevel(ReadLogLevel());
		});

		Application.Run(new MainForm(loggerFactory));
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static LogLevel ReadLogLevel()
	{
		string? configured = Environment.GetEnvironmentVariable("RDPAUDIT_RdpAudit__LogLevel");
		return Enum.TryParse(configured, ignoreCase: true, out LogLevel level) ? level : LogLevel.Information;
	}
}
