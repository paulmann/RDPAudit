// File:    src/RdpAudit.Web/wwwroot/assets/js/rdpaudit-web.js
// Module:  RdpAudit.Web (wwwroot)
// Purpose: Browser logic of the read-only web dashboard. Strict CSP ('self')
//          permits only this external file, so there are NO inline handlers,
//          NO eval, NO innerHTML: every rendered value goes through
//          document.createElement + textContent, which also neutralizes any
//          data coming back from the REST API. The page never sends credentials:
//          the server-side proxy injects the shared bearer token.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

(function () {
  'use strict';

  // ------------------------------------------------------------------ utils
  function $(id) {
    return document.getElementById(id);
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function fmtUtc(value) {
    if (value === null || value === undefined || value === '') {
      return '-';
    }
    var date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return String(value);
    }
    return date.toLocaleString();
  }

  function fmtNum(value) {
    if (value === null || value === undefined || value === '') {
      return '0';
    }
    var num = Number(value);
    return Number.isFinite(num) ? num.toLocaleString() : String(value);
  }

  function severityBadgeClass(severity) {
    var s = String(severity || '').toLowerCase();
    if (s === 'critical' || s === 'high' || s === 'error') {
      return 'badge critical';
    }
    if (s === 'medium' || s === 'warning') {
      return 'badge medium';
    }
    if (s === 'low' || s === 'info') {
      return 'badge low';
    }
    return 'badge neutral';
  }

  function threatBadgeClass(level) {
    var s = String(level || '').toLowerCase();
    if (s === 'critical' || s === 'high') {
      return 'badge critical';
    }
    if (s === 'medium' || s === 'elevated') {
      return 'badge medium';
    }
    if (s === 'low') {
      return 'badge low';
    }
    return 'badge neutral';
  }

  // ------------------------------------------------------------------ state
  var AUTO_REFRESH_MS = 30000;
  var activeTab = 'overview';
  var timer = null;

  // ------------------------------------------------------------------ fetch
  function buildUrl(path, params) {
    var url = path;
    var first = true;
    Object.keys(params).forEach(function (key) {
      var value = params[key];
      if (value === null || value === undefined || value === '') {
        return;
      }
      url += (first ? '?' : '&') + encodeURIComponent(key) + '=' + encodeURIComponent(value);
      first = false;
    });
    return url;
  }

  function showError(detail) {
    var banner = $('error-banner');
    banner.textContent = detail || 'The RdpAudit service is unreachable.';
    banner.classList.remove('hidden');
  }

  function hideError() {
    $('error-banner').classList.add('hidden');
  }

  async function apiGet(path, params) {
    var res = await fetch(buildUrl(path, params || {}), {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store'
    });
    if (!res.ok) {
      var detail = 'Request failed with status ' + res.status + '.';
      try {
        var problem = await res.json();
        if (problem && problem.detail) {
          detail = problem.detail;
        } else if (problem && problem.title) {
          detail = problem.title;
        }
      } catch (ignore) {
        // Non-JSON error body - keep the status-based detail.
      }
      throw new Error(detail);
    }
    return res.json();
  }

  // ------------------------------------------------------------------ render helpers
  function renderTable(container, columns, rows, emptyText) {
    clear(container);
    if (!rows || rows.length === 0) {
      container.appendChild(el('div', 'empty', emptyText || 'No rows.'));
      return;
    }
    var table = el('table');
    var thead = el('thead');
    var headRow = el('tr');
    columns.forEach(function (column) {
      headRow.appendChild(el('th', null, column.title));
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el('tbody');
    rows.forEach(function (row) {
      var tr = el('tr');
      columns.forEach(function (column) {
        var value = column.value(row);
        var td = el('td');
        if (column.badge) {
          var badge = el('span', column.badge(value, row), value);
          td.appendChild(badge);
        } else {
          td.textContent = value === null || value === undefined ? '' : String(value);
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.appendChild(table);
  }

  function renderStatCards(container, items) {
    clear(container);
    items.forEach(function (item) {
      var card = el('div', 'stat-card');
      card.appendChild(el('span', 'label', item.label));
      card.appendChild(el('span', 'value', item.value));
      container.appendChild(card);
    });
  }

  function setPill(text) {
    $('last-updated').textContent = text;
  }

  // ------------------------------------------------------------------ dashboard sections
  async function loadOverview() {
    var status = await apiGet('/api/status', {});
    return renderOverview(status);
  }

  function renderOverview(status) {
    renderStatCards($('status-cards'), [
      { label: 'Version', value: status.version || '-' },
      { label: 'Events captured', value: fmtNum(status.eventsCaptured) },
      { label: 'Events dropped', value: fmtNum(status.eventsDropped) },
      { label: 'Alerts raised', value: fmtNum(status.alertsRaised) },
      { label: 'Active sessions', value: fmtNum(status.activeSessions) },
      { label: 'Uptime', value: String(status.uptime || '-') }
    ]);

    var channels = status.channelStatus || {};
    var rows = Object.keys(channels).map(function (channel) {
      return { channel: channel, state: channels[channel] };
    });
    renderTable(
      $('channel-status'),
      [
        { title: 'Channel', value: function (row) { return row.channel; } },
        {
          title: 'State',
          value: function (row) { return row.state; },
          badge: function (value) {
            var s = String(value || '').toLowerCase();
            return s.indexOf('ok') !== -1 || s.indexOf('active') !== -1 || s.indexOf('healthy') !== -1
              ? 'badge safe'
              : 'badge neutral';
          }
        }
      ],
      rows,
      'No channel status reported.'
    );
  }

  async function loadAttacks() {
    var params = { limit: 500 };
    var ipQuery = $('attacks-ip-query').value.trim();
    if (ipQuery) {
      params.ipQuery = ipQuery;
    }
    var minThreat = $('attacks-min-threat').value.trim();
    if (minThreat) {
      params.minThreatScore = minThreat;
    }
    if ($('attacks-only-blocked').checked) {
      params.onlyBlocked = 'true';
    }
    var stats = await apiGet('/api/attacks', params);
    renderAttacks(stats);
  }

  function renderAttacks(stats) {
    renderStatCards($('attacks-summary'), [
      { label: 'Failed logons', value: fmtNum(stats.failedLogons) },
      { label: 'Successful logons', value: fmtNum(stats.successfulLogons) },
      { label: 'Distinct source IPs', value: fmtNum(stats.distinctSourceIps) },
      { label: 'Alerts raised', value: fmtNum(stats.alertsRaised) },
      { label: 'Auto-blocked', value: fmtNum(stats.addressesAutoBlocked) },
      { label: 'Matching rows', value: fmtNum(stats.totalMatching) }
    ]);
    var entries = stats.entries || [];
    renderTable(
      $('attacks-table'),
      [
        { title: 'IP', value: function (row) { return row.displayIp || row.ip; } },
        { title: 'Attempts', value: function (row) { return fmtNum(row.totalAttempts); } },
        { title: 'Failed', value: function (row) { return fmtNum(row.failed); } },
        { title: 'Successful', value: function (row) { return fmtNum(row.successful); } },
        { title: 'Last seen', value: function (row) { return fmtUtc(row.lastSeenUtc); } },
        { title: 'Threat score', value: function (row) { return fmtNum(row.threatScore); } },
        {
          title: 'Level',
          value: function (row) { return row.threatLevel || '-'; },
          badge: function (value) { return threatBadgeClass(value); }
        },
        {
          title: 'Blocked',
          value: function (row) { return row.isBlocked ? 'yes' : 'no'; },
          badge: function (value, row) { return row.isBlocked ? 'badge blocked' : 'badge safe'; }
        }
      ],
      entries,
      'No attack statistics in the selected window.'
    );
  }

  async function loadAddresses() {
    var addresses = await apiGet('/api/addresses', {});
    renderAddresses(addresses);
  }

  function renderAddresses(addresses) {
    var list = Array.isArray(addresses) ? addresses : [];
    renderTable(
      $('addresses-table'),
      [
        { title: 'IP', value: function (row) { return row.ip; } },
        { title: 'Failures', value: function (row) { return fmtNum(row.failCount); } },
        { title: 'Successes', value: function (row) { return fmtNum(row.successCount); } },
        { title: 'First seen', value: function (row) { return fmtUtc(row.firstSeen); } },
        { title: 'Last seen', value: function (row) { return fmtUtc(row.lastSeen); } },
        { title: 'Threat score', value: function (row) { return fmtNum(row.threatScore); } },
        {
          title: 'Blocked',
          value: function (row) { return row.isBlocked ? 'yes' : 'no'; },
          badge: function (value, row) { return row.isBlocked ? 'badge blocked' : 'badge safe'; }
        },
        { title: 'Reason', value: function (row) { return row.blockReason || ''; } },
        { title: 'Public', value: function (row) { return row.isPublicIp ? 'yes' : 'no'; } }
      ],
      list,
      'No IP aggregates recorded yet.'
    );
  }

  async function loadSessions() {
    var sessions = await apiGet('/api/sessions', {});
    renderSessions(sessions);
  }

  function renderSessions(sessions) {
    var list = Array.isArray(sessions) ? sessions : [];
    renderTable(
      $('sessions-table'),
      [
        { title: 'User', value: function (row) { return row.userName || '-'; } },
        { title: 'Domain', value: function (row) { return row.domain || '-'; } },
        { title: 'Source IP', value: function (row) { return row.sourceIp || '-'; } },
        { title: 'Connected', value: function (row) { return fmtUtc(row.connectUtc); } },
        { title: 'Disconnected', value: function (row) { return fmtUtc(row.disconnectUtc); } },
        { title: 'Logon type', value: function (row) { return row.logonType === null || row.logonType === undefined ? '-' : String(row.logonType); } },
        {
          title: 'Status',
          value: function (row) { return row.status || '-'; },
          badge: function (value) {
            var s = String(value || '').toLowerCase();
            if (s === 'active') {
              return 'badge safe';
            }
            if (s === 'disconnected') {
              return 'badge medium';
            }
            return 'badge neutral';
          }
        }
      ],
      list,
      'No RDP sessions recorded yet.'
    );
  }

  async function loadAlerts() {
    var alerts = await apiGet('/api/alerts', {});
    renderAlerts(alerts);
  }

  function renderAlerts(alerts) {
    var list = Array.isArray(alerts) ? alerts : [];
    renderTable(
      $('alerts-table'),
      [
        { title: 'Time', value: function (row) { return fmtUtc(row.timeUtc); } },
        { title: 'Rule', value: function (row) { return row.ruleId || '-'; } },
        {
          title: 'Severity',
          value: function (row) { return row.severity || '-'; },
          badge: function (value) { return severityBadgeClass(value); }
        },
        { title: 'Source IP', value: function (row) { return row.sourceIp || '-'; } },
        { title: 'User', value: function (row) { return row.userName || '-'; } },
        { title: 'Message', value: function (row) { return row.message || ''; } },
        {
          title: 'Acknowledged',
          value: function (row) { return row.acknowledged ? 'yes' : 'no'; },
          badge: function (value, row) { return row.acknowledged ? 'badge safe' : 'badge medium'; }
        }
      ],
      list,
      'No alerts recorded yet.'
    );
  }

  async function loadEvents() {
    var params = { limit: 100 };
    var eventId = $('events-event-id').value.trim();
    if (eventId) {
      params.eventId = eventId;
    }
    var sourceIp = $('events-source-ip').value.trim();
    if (sourceIp) {
      params.sourceIp = sourceIp;
    }
    var limit = $('events-limit').value.trim();
    if (limit) {
      params.limit = limit;
    }
    var page = await apiGet('/api/events', params);
    renderEvents(page);
  }

  function renderEvents(page) {
    $('events-meta').textContent = 'Showing ' + (page.events ? page.events.length : 0) + ' of ' + fmtNum(page.total) + ' events.';
    renderTable(
      $('events-table'),
      [
        { title: 'Time (UTC)', value: function (row) { return fmtUtc(row.timeUtc); } },
        { title: 'Event id', value: function (row) { return String(row.eventId); } },
        { title: 'Channel', value: function (row) { return row.channel || ''; } },
        { title: 'Source IP', value: function (row) { return row.sourceIp || '-'; } },
        { title: 'User', value: function (row) { return row.userName || '-'; } },
        { title: 'Status', value: function (row) { return row.status || '-'; } }
      ],
      page.events || [],
      'No events match the selected filters.'
    );
  }

  // ------------------------------------------------------------------ refresh orchestration
  var loaders = {
    overview: loadOverview,
    attacks: loadAttacks,
    addresses: loadAddresses,
    sessions: loadSessions,
    alerts: loadAlerts,
    events: loadEvents
  };

  async function refreshActiveTab() {
    hideError();
    $('refresh-btn').disabled = true;
    try {
      await loaders[activeTab]();
      setPill('Updated ' + new Date().toLocaleTimeString());
    } catch (err) {
      showError(err && err.message ? err.message : 'The RdpAudit service is unreachable.');
    } finally {
      $('refresh-btn').disabled = false;
    }
  }

  // ------------------------------------------------------------------ tabs
  function switchTab(tabId) {
    activeTab = tabId;
    var tabs = document.querySelectorAll('.tab');
    for (var i = 0; i < tabs.length; i++) {
      var tab = tabs[i];
      var selected = tab.getAttribute('data-tab') === tabId;
      tab.classList.toggle('active', selected);
      tab.setAttribute('aria-selected', selected ? 'true' : 'false');
    }
    var panels = document.querySelectorAll('.tab-panel');
    for (var j = 0; j < panels.length; j++) {
      var panel = panels[j];
      panel.classList.toggle('active', panel.id === 'tab-' + tabId);
    }
    refreshActiveTab();
  }

  // ------------------------------------------------------------------ theme
  function applyTheme(dark) {
    document.body.classList.toggle('dark', dark);
    $('theme-toggle').textContent = dark ? '\u2600' : '\u263D';
    try {
      localStorage.setItem('rdpaudit-web-theme', dark ? 'dark' : 'light');
    } catch (ignore) {
      // Storage can be unavailable - the theme still applies for this page view.
    }
  }

  function initTheme() {
    var saved = null;
    try {
      saved = localStorage.getItem('rdpaudit-web-theme');
    } catch (ignore) {
      saved = null;
    }
    if (saved === 'dark' || saved === 'light') {
      applyTheme(saved === 'dark');
    }
  }

  // ------------------------------------------------------------------ wiring
  function wire() {
    $('refresh-btn').addEventListener('click', function () {
      refreshActiveTab();
    });
    $('theme-toggle').addEventListener('click', function () {
      applyTheme(!document.body.classList.contains('dark'));
    });
    $('attacks-apply').addEventListener('click', function () {
      refreshActiveTab();
    });
    $('events-apply').addEventListener('click', function () {
      refreshActiveTab();
    });
    var tabs = document.querySelectorAll('.tab');
    for (var i = 0; i < tabs.length; i++) {
      (function (tab) {
        tab.addEventListener('click', function () {
          switchTab(tab.getAttribute('data-tab'));
        });
      })(tabs[i]);
    }
    timer = setInterval(function () {
      refreshActiveTab();
    }, AUTO_REFRESH_MS);
  }

  // ------------------------------------------------------------------ boot
  initTheme();
  wire();
  refreshActiveTab();
})();
