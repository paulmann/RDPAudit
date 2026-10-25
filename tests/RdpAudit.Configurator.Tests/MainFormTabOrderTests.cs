/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : MainFormTabOrderTests.cs
// Project: RdpAudit.Configurator.Tests (RdpAudit.Configurator.Tests)
// Purpose: P4-18 Step 9 verification for the Cross-Host tab: the Configurator tab order is fixed
//          and covered by a test. The rendered MainForm tab titles must match MainForm.OrderedPageTitles
//          one-to-one, and the Cross-Host tab must sit between MikroTik and Diagnostic. The form
//          is constructed on a dedicated STA thread because WinForms controls require an STA
//          apartment; no handle is created, so the test never touches a live named pipe.
//          The STA host is the shared StaTestHarness, whose join on the STA thread carries a deadline
//          (and gives the whole class a hard time budget). This class used to start a raw Thread and
//          call Join() with no bound: its bodies are synchronous today, so that could not deadlock -
//          but the moment a body grows an await against a page's ConfigureAwait(true) continuation,
//          an unbounded join turns a regression into a hung test run instead of a failed test (the
//          A4 hang). A deadline costs nothing here and removes that possibility for good.
// Depends: MainForm, StaTestHarness, WinForms, xunit
// Extends: When a new Configurator page is added, extend this test with its position.

using System.Runtime.Versioning;
using RdpAudit.Configurator.Forms;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class MainFormTabOrderTests
{
	/// <summary>Per-class STA host. Every form-constructing body runs on this harness's STA thread,
	/// which is joined with a deadline (30 s per body) and capped by the class budget (2 minutes), so a
	/// future regression fails with a readable message instead of wedging the run.</summary>
	private readonly StaTestHarness _ui = new(nameof(MainFormTabOrderTests));

	[Fact]
	public void Ordering_CrossHostTab_SitsBetweenMikroTikAndDiagnostic()
	{
		List<string> titles = new(MainForm.OrderedPageTitles);

		int crossHost = titles.IndexOf("\U0001F517 Cross-Host");
		int mikroTik = titles.IndexOf("\U0001F4F6 MikroTik");
		int diagnostics = titles.IndexOf("\U0001FA7A Diagnostic");

		Assert.True(crossHost > 0, "Cross-Host tab is missing from OrderedPageTitles.");
		Assert.True(mikroTik >= 0, "MikroTik tab is missing from OrderedPageTitles.");
		Assert.True(diagnostics >= 0, "Diagnostic tab is missing from OrderedPageTitles.");
		Assert.Equal(mikroTik + 2, crossHost); // the Zabbix tab sits between MikroTik and Cross-Host
		Assert.Equal(crossHost + 2, diagnostics); // Session Map sits between Cross-Host and Diagnostic
	}

	/// <summary>The Zabbix tab belongs to the outbound-integration group: it follows MikroTik and
	/// precedes Cross-Host.</summary>
	[Fact]
	public void Ordering_ZabbixTab_SitsBetweenMikroTikAndCrossHost()
	{
		List<string> titles = new(MainForm.OrderedPageTitles);

		int zabbix = titles.IndexOf("\U0001F4EE Zabbix");
		int mikroTik = titles.IndexOf("\U0001F4F6 MikroTik");
		int crossHost = titles.IndexOf("\U0001F517 Cross-Host");

		Assert.True(zabbix > 0, "Zabbix tab is missing from OrderedPageTitles.");
		Assert.Equal(mikroTik + 1, zabbix);
		Assert.Equal(zabbix + 1, crossHost);
	}

	[Fact]
	public void Ordering_SessionMapTab_SitsBetweenCrossHostAndDiagnostic()
	{
		List<string> titles = new(MainForm.OrderedPageTitles);

		int sessionMap = titles.IndexOf("\U0001F5FA\uFE0F Session Map");
		int crossHost = titles.IndexOf("\U0001F517 Cross-Host");
		int diagnostics = titles.IndexOf("\U0001FA7A Diagnostic");

		Assert.True(sessionMap > 0, "Session Map tab is missing from OrderedPageTitles.");
		Assert.True(crossHost >= 0, "Cross-Host tab is missing from OrderedPageTitles.");
		Assert.True(diagnostics >= 0, "Diagnostic tab is missing from OrderedPageTitles.");
		Assert.Equal(crossHost + 1, sessionMap);
		Assert.Equal(sessionMap + 1, diagnostics);
	}

	[Fact]
	public void MainForm_ContainSessionMap()
	{
		bool found = false;
		_ui.Run(() =>
		{
			using MainForm form = new();
			TabControl tabs = form.Controls.OfType<TabControl>().Single();
			found = tabs.TabPages.Cast<TabPage>().Any(p => p.Text == "\U0001F5FA\uFE0F Session Map");
		});

		Assert.True(found, "The rendered MainForm does not contain the Session Map tab.");
	}

	[Fact]
	public void MainForm_RenderedTabs_MatchOrderedPageTitlesExactly()
	{
		List<string> rendered = new();
		_ui.Run(() =>
		{
			using MainForm form = new();
			TabControl tabs = form.Controls.OfType<TabControl>().Single();
			rendered.AddRange(tabs.TabPages.Cast<TabPage>().Select(p => p.Text));
		});

		Assert.Equal(MainForm.OrderedPageTitles, rendered);
	}

	[Fact]
	public void Ordering_NotificationsTab_SitsBetweenDatabaseAndSettings()
	{
		List<string> titles = new(MainForm.OrderedPageTitles);

		int notifications = titles.IndexOf("\U0001F514 Notifications");
		int database = titles.IndexOf("\U0001F5C4\uFE0F Database");
		int settings = titles.IndexOf("\U0001F527 Settings");

		Assert.True(notifications > 0, "Notifications tab is missing from OrderedPageTitles.");
		Assert.True(database >= 0, "Database tab is missing from OrderedPageTitles.");
		Assert.True(settings >= 0, "Settings tab is missing from OrderedPageTitles.");
		Assert.Equal(database + 1, notifications);
		Assert.Equal(notifications + 1, settings);
	}

	/// <summary>Stage 3: the Database tab must sit between Tools Diag and Notifications, and Settings
	/// must stay the last page.</summary>
	[Fact]
	public void Ordering_DatabaseTab_SitsBetweenToolsDiagAndNotifications()
	{
		List<string> titles = new(MainForm.OrderedPageTitles);

		int database = titles.IndexOf("\U0001F5C4\uFE0F Database");
		int toolsDiag = titles.IndexOf("\U0001F9EA Tools Diag");
		int notifications = titles.IndexOf("\U0001F514 Notifications");

		Assert.True(database > 0, "Database tab is missing from OrderedPageTitles.");
		Assert.True(toolsDiag >= 0, "Tools Diag tab is missing from OrderedPageTitles.");
		Assert.True(notifications >= 0, "Notifications tab is missing from OrderedPageTitles.");
		Assert.Equal(toolsDiag + 1, database);
		Assert.Equal(database + 1, notifications);
		Assert.Equal(titles.Count - 1, titles.IndexOf("\U0001F527 Settings"));
	}

	[Fact]
	public void MainForm_RenderedTabs_ContainDatabase()
	{
		bool found = false;
		_ui.Run(() =>
		{
			using MainForm form = new();
			TabControl tabs = form.Controls.OfType<TabControl>().Single();
			found = tabs.TabPages.Cast<TabPage>().Any(p => p.Text == "\U0001F5C4\uFE0F Database");
		});

		Assert.True(found, "The rendered MainForm does not contain the Database tab.");
	}

	[Fact]
	public void MainForm_RenderedTabs_ContainNotifications()
	{
		bool found = false;
		_ui.Run(() =>
		{
			using MainForm form = new();
			TabControl tabs = form.Controls.OfType<TabControl>().Single();
			found = tabs.TabPages.Cast<TabPage>().Any(p => p.Text == "\U0001F514 Notifications");
		});

		Assert.True(found, "The rendered MainForm does not contain the Notifications tab.");
	}

	[Fact]
	public void Ordering_WebAccessTab_SitsBetweenServiceAndRdpConfiguration()
	{
		List<string> titles = new(MainForm.OrderedPageTitles);

		int webAccess = titles.IndexOf("\U0001F578\uFE0F Web Access");
		int service = titles.IndexOf("⚙️ Service");
		int rdpConfiguration = titles.IndexOf("\U0001F5A5️ RDP Configuration");

		Assert.True(webAccess > 0, "Web Access tab is missing from OrderedPageTitles.");
		Assert.True(service >= 0, "Service tab is missing from OrderedPageTitles.");
		Assert.True(rdpConfiguration >= 0, "RDP Configuration tab is missing from OrderedPageTitles.");
		Assert.Equal(service + 1, webAccess);
		Assert.Equal(webAccess + 1, rdpConfiguration);
	}

	[Fact]
	public void Ordering_ProcessAlertsTab_SitsBetweenRdpClientsAndAbuseIpDb()
	{
		List<string> titles = new(MainForm.OrderedPageTitles);

		int processAlerts = titles.IndexOf("\U0001F9ED Process Alerts");
		int rdpClients = titles.IndexOf("\U0001F310 RDP Clients");
		int abuseIpDb = titles.IndexOf("\U0001F9FE AbuseIPDB");

		Assert.True(processAlerts > 0, "Process Alerts tab is missing from OrderedPageTitles.");
		Assert.True(rdpClients >= 0, "RDP Clients tab is missing from OrderedPageTitles.");
		Assert.True(abuseIpDb >= 0, "AbuseIPDB tab is missing from OrderedPageTitles.");
		Assert.Equal(rdpClients + 1, processAlerts);
		Assert.Equal(processAlerts + 1, abuseIpDb);
	}

	[Fact]
	public void MainForm_RenderedTabs_ContainCrossHost()
	{
		bool found = false;
		_ui.Run(() =>
		{
			using MainForm form = new();
			TabControl tabs = form.Controls.OfType<TabControl>().Single();
			found = tabs.TabPages.Cast<TabPage>().Any(p => p.Text == "\U0001F517 Cross-Host");
		});

		Assert.True(found, "The rendered MainForm does not contain the Cross-Host tab.");
	}
}
