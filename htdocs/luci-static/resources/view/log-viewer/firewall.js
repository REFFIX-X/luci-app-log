'use strict';
'require view';
'require fs';
'require rpc';
'require ui';

const MAX_LINES = 1500;
const PAGE_SIZE = 100;
const SERVICES = {
  21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',69:'TFTP',80:'HTTP',
  110:'POP3',123:'NTP',135:'MS RPC',139:'NetBIOS',143:'IMAP',161:'SNMP',
  389:'LDAP',443:'HTTPS',445:'SMB',500:'IKE',514:'Syslog',548:'AFP',554:'RTSP',
  587:'SMTP Submit',631:'IPP',873:'rsync',993:'IMAPS',995:'POP3S',1080:'SOCKS',
  1194:'OpenVPN',1433:'MS SQL',1521:'Oracle',1723:'PPTP',1883:'MQTT',1900:'SSDP',
  2049:'NFS',2222:'Alt SSH',2375:'Docker API',2376:'Docker TLS',3000:'Web UI',
  3306:'MySQL',3389:'RDP',4500:'IPsec NAT-T',5000:'Web/App',5001:'HTTPS/App',
  5060:'SIP',5061:'SIP TLS',5432:'PostgreSQL',5555:'ADB',5900:'VNC',
  5985:'WinRM',5986:'WinRM TLS',6379:'Redis',6443:'Kubernetes API',
  6667:'IRC',7001:'WebLogic',7443:'HTTPS Alt',7777:'Game/Service',
  8000:'HTTP Alt',8008:'HTTP Alt',8080:'HTTP Proxy',8081:'HTTP Alt',
  8088:'HTTP Alt',8443:'HTTPS Alt',8888:'HTTP Alt',9000:'Web/App',
  9042:'Cassandra',9090:'Web/App',9200:'Elasticsearch',9300:'Elasticsearch',
  9418:'Git',10000:'Webmin',11211:'Memcached',27017:'MongoDB'
};

function esc(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}

function csvCell(value) {
  let text = String(value == null ? '' : value);
  if (/^[\t\r\n ]*[=+\-@]/.test(text)) text = "'" + text;
  return '"' + text.replace(/"/g, '""') + '"';
}

function isPublic(ip) {
  if (!ip || ip === '-' || ip === '0.0.0.0') return false;
  if (ip.indexOf(':') >= 0) return false;
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  return !(p[0] === 10 || p[0] === 127 || p[0] === 0 || p[0] >= 224 ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127));
}

function parseFields(line) {
  const result = {};
  const re = /([A-Z][A-Z0-9_]*)=("[^"]*"|\S+)/g;
  let match;
  while ((match = re.exec(line)) !== null)
    result[match[1]] = match[2].replace(/^"|"$/g, '');
  return result;
}

function parseRouterTimestamp(timestamp, routerOffset) {
  const fields = String(timestamp || '').match(/^[A-Z][a-z]{2}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$/);
  const offset = String(routerOffset || '').match(/^([+-])(\d{2})(\d{2})$/);
  if (!fields || !offset) return null;
  const months = {Jan:0, Feb:1, Mar:2, Apr:3, May:4, Jun:5, Jul:6, Aug:7, Sep:8, Oct:9, Nov:10, Dec:11};
  const month = months[fields[1]];
  if (month == null) return null;
  const wallTime = Date.UTC(Number(fields[6]), month, Number(fields[2]), Number(fields[3]), Number(fields[4]), Number(fields[5]));
  const minutesEast = (Number(offset[2]) * 60 + Number(offset[3])) * (offset[1] === '-' ? -1 : 1);
  return wallTime - minutesEast * 60000;
}

function formatLogreadTimestamp(epochMs, routerOffset) {
  const ms = Number(epochMs);
  const offset = String(routerOffset || '').match(/^([+-])(\d{2})(\d{2})$/);
  if (!Number.isFinite(ms) || ms <= 0 || !offset) return '';
  const minutesEast = (Number(offset[2]) * 60 + Number(offset[3])) * (offset[1] === '-' ? -1 : 1);
  const wall = new Date(ms + minutesEast * 60000);
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const pad = n => String(n).padStart(2, '0');
  return days[wall.getUTCDay()] + ' ' + months[wall.getUTCMonth()] + ' ' + wall.getUTCDate() + ' ' +
    pad(wall.getUTCHours()) + ':' + pad(wall.getUTCMinutes()) + ':' + pad(wall.getUTCSeconds()) + ' ' +
    wall.getUTCFullYear();
}

function parseLine(line, index, routerOffset) {
  const infraHit = line.includes('INFRA_PORT_HIT:');
  const hasPacketTuple = /SRC=\S+.*DPT=\d+/.test(line);
  const blockMarker = /\b(?:DROP|REJECT)\b/i.test(line) ||
    /(?:^|[\s:])[A-Z0-9_-]*(?:BLOCKED|BLOCK|DROP|REJECT):/i.test(line);
  const allowMarker =
    /(?:^|[\s:])[A-Z0-9_-]*(?:ALLOWED|ALLOW|ACCEPTED|ACCEPT|PASSED|PASS):/i.test(line);
  const markerMatch = line.match(/(?:^|\s)([A-Z][A-Z0-9_-]{1,39}):/);
  const marker = markerMatch ? markerMatch[1] : '';

  let prefix = '';
  let kind = '';
  if (infraHit) {
    prefix = 'INFRA_PORT_HIT';
    kind = 'Blocked';
  }
  else if (hasPacketTuple && blockMarker) {
    prefix = 'FIREWALL_BLOCK';
    kind = 'Blocked';
  }
  else if (hasPacketTuple && allowMarker) {
    prefix = 'FIREWALL_ALLOW';
    kind = 'Allowed';
  }
  else return null;

  const fields = parseFields(line);
  const port = Number(fields.DPT || 0);
  const timestamp = (line.match(/^([A-Z][a-z]{2}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})/) || ['', ''])[1];
  const routerTimestampMs = timestamp ? parseRouterTimestamp(timestamp, routerOffset) : null;
  const timestampMs = routerTimestampMs == null && timestamp ? Date.parse(timestamp) : routerTimestampMs;

  return {
    id: index,
    rawLine: line,
    timestamp: timestamp || 'Recent',
    timestampMs: Number.isFinite(timestampMs) ? timestampMs : null,
    kind: kind,
    source: fields.SRC || '',
    destination: fields.DST || '',
    dport: port,
    service: SERVICES[port] || 'Unknown service',
    protocol: (fields.PROTO || '?').toUpperCase(),
    sport: fields.SPT || '',
    iface: fields.IN || '',
    ttl: fields.TTL || '',
    flags: line.includes('SYN') ? 'SYN' : line.includes('RST') ? 'RST' :
      (fields.PROTO === 'UDP' ? 'UDP packet' : ''),
    prefix: prefix,
    marker: marker || prefix,
    policyLabel: '',
    policyNote: ''
  };
}

const BUNDLED_FLAGS = new Set('ae au be br ca ch cn cz de es fi fr gb hk id il in ir it jp kr mx my nl no ph pl pt ro ru sa se sg th tr tw ua us vn za'.split(' '));

function countryFlag(code) {
  if (!/^[A-Z]{2}$/.test(code || ''))
    return '<span class="fw-flag-fallback" title="Country unavailable">🌐</span>';
  if (!BUNDLED_FLAGS.has(code.toLowerCase()))
    return '<span class="fw-flag-fallback" title="Flag not bundled for ' + esc(code) + '">🌐</span>';

  // Flags are bundled locally. This avoids LuCI CSP restrictions on external image hosts.
  return '<img class="fw-flag-img" src="/luci-static/resources/log-viewer/flags/' +
    code.toLowerCase() + '.svg" alt="' + esc(code) +
    '" width="20" loading="lazy" decoding="async">';
}

function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const link = E('a', {href: url, download: filename});
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const callLogRead = rpc.declare({
  object: 'log',
  method: 'read',
  params: ['lines', 'stream', 'oneshot'],
  expect: { log: [] }
});

let historyDatabasePromise = null;
function openHistoryDatabase() {
  if (!window.indexedDB) return Promise.reject(new Error('IndexedDB is unavailable in this browser'));
  if (historyDatabasePromise) return historyDatabasePromise;
  historyDatabasePromise = new Promise((resolve, reject) => {
    const request = indexedDB.open('reffix-firewall-log', 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('events')) {
        const store = db.createObjectStore('events', {keyPath: 'key'});
        store.createIndex('timestampMs', 'timestampMs', {unique: false});
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Unable to open local event history'));
    request.onblocked = () => reject(new Error('Close other Firewall Log tabs to upgrade local history'));
  }).catch(error => {
    historyDatabasePromise = null;
    throw error;
  });
  return historyDatabasePromise;
}

function historyRequest(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Local history request failed'));
  });
}

function historyTransactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error || new Error('Local history write failed'));
    transaction.onabort = () => reject(transaction.error || new Error('Local history write was cancelled'));
  });
}

return view.extend({
  viewName: 'firewall',
  title: _('Firewall Log'),
  events: [],
  geoCache: {},
  geoCacheAt: {},
  geoLookupInFlight: new Map(),
  kindFilter: 'all',
  protoFilter: 'all',
  timeFilter: 'all',
  sourceFilter: '',
  portFilter: null,
  paused: false,
  policyRules: [],
  policyRulesLoaded: false,
  trafficContextLoaded: false,
  watchConfig: null,
  watchConfigLoaded: false,
  routerClockAtSync: 0,
  routerClockSyncedAt: 0,
  wanInterfaces: [],
  exposedPorts: {},
  showAllPorts: false,
  maxEntries: 100,
  historyRetention: 'off',
  historyCache: null,
  historySeedPending: false,
  timelineRange: null,
  liveEvents: [],
  sourceLineCount: 0,
  logReadLimit: MAX_LINES,
  watchConfigRequest: 0,
  lastCollectedAt: 0,
  lastRawData: null,
  geoStatus: null,
  geoStatusCheckedAt: 0,
  showReputation: false,
  filterPresets: [],
  refreshGeneration: 0,

  getLogData: async function() {
    // ubus log.read is the OpenWrt 25.12 path. file.exec of logread is capped
    // at 256 KiB, which silently drops the newest lines of a 1,500-line tail.
    // OpenWrt also installs the binary as /usr/libexec/logread-ubox and only
    // optionally links /sbin/logread, so that path stays as a fallback.
    const offset = (this.watchConfig && this.watchConfig.router_offset) || '+0000';
    const formatEntries = (entries, limit) => {
      this.logReadLimit = limit;
      return entries.map(entry => {
        const msg = String(entry && entry.msg != null ? entry.msg : '').replace(/[\r\n]+/g, ' ').trim();
        if (!msg) return '';
        const stamp = formatLogreadTimestamp(entry && entry.time, offset);
        return stamp ? (stamp + ' ' + msg) : msg;
      }).filter(Boolean).join('\n');
    };
    const readEntries = async (limit) => {
      const entries = await callLogRead(limit, false, true);
      return Array.isArray(entries) ? entries : null;
    };

    try {
      const entries = await readEntries(MAX_LINES);
      if (entries) return formatEntries(entries, MAX_LINES);
    }
    catch (e) {
      try {
        const entries = await readEntries(400);
        if (entries) return formatEntries(entries, 400);
      }
      catch (e2) {}
    }

    this.logReadLimit = MAX_LINES;
    const commands = ['/sbin/logread', '/usr/sbin/logread', '/usr/libexec/logread-ubox'];
    let lastError = new Error('logread not found');
    for (let i = 0; i < commands.length; i++) {
      try {
        return await fs.exec_direct(commands[i], ['-l', String(MAX_LINES)], 'text');
      }
      catch (e) {
        lastError = e;
      }
    }
    throw lastError;
  },

  loadPolicyRules: async function() {
    if (this.policyRulesLoaded) return;
    this.policyRulesLoaded = true;
    try {
      const raw = await fs.read('/etc/log-viewer/policies.json');
      const config = JSON.parse(raw || '{}');
      this.policyRules = Array.isArray(config.policies) ? config.policies : [];
    }
    catch (e) {
      this.policyRules = [];
    }
  },

  loadWatchConfig: async function(force) {
    if (this.watchConfigLoaded && !force) return;
    const request = ++this.watchConfigRequest;
    this.watchConfigLoaded = true;
    try {
      const raw = await fs.exec_direct('/usr/sbin/infra-port-watch', ['get'], 'text');
      if (request !== this.watchConfigRequest) return;
      this.watchConfig = JSON.parse(raw || '{}');
      this.routerClockAtSync = Number(this.watchConfig.router_time || 0) * 1000;
      this.routerClockSyncedAt = Date.now();
    }
    catch (e) {
      if (request !== this.watchConfigRequest) return;
      this.watchConfig = null;
    }
  },

  loadTrafficContext: function() {
    if (!this.trafficContextLoaded) {
      this.trafficContextLoaded = true;
      // Use explicitly configured allow labels as useful defaults; the user can
      // edit these independently in this browser's traffic-context settings.
      this.exposedPorts = {};
      this.policyRules.forEach(rule => {
        if (!rule || !/_ALLOW$|_EXPOSED?$|_FORWARD$/i.test(String(rule.marker || '')) ||
            !Number.isInteger(Number(rule.port)) || Number(rule.port) < 1 || Number(rule.port) > 65535)
          return;
        this.exposedPorts[Number(rule.port)] = String(rule.label || ('Port ' + rule.port));
      });

      try {
        const saved = JSON.parse(localStorage.getItem('reffix-log-viewer.traffic-context') || 'null');
        if (saved && typeof saved === 'object' && saved.exposedPorts && typeof saved.exposedPorts === 'object')
          this.exposedPorts = Object.fromEntries(Object.entries(saved.exposedPorts)
            .filter(([port, label]) => /^\d{1,5}$/.test(port) && Number(port) > 0 && Number(port) <= 65535 && typeof label === 'string')
            .map(([port, label]) => [Number(port), label.trim() || ('Port ' + port)]));
      }
      catch (e) {}
    }
    const activeInterface = this.watchConfig && (this.watchConfig.active_interface ||
      (this.watchConfig.wan_interface !== 'auto' ? this.watchConfig.wan_interface : ''));
    if (activeInterface) this.wanInterfaces = [String(activeInterface).trim().toLowerCase()];
  },

  applyTrafficContext: function(event) {
    if (event.prefix !== 'INFRA_PORT_HIT') return event;

    event.kind = event.baseKind || 'Blocked';
    event.policyLabel = event.basePolicyLabel || 'WAN watchlist';
    event.policyNote = event.basePolicyNote || '';

    const iface = String(event.iface || '').toLowerCase();
    const onWan = !this.wanInterfaces.length || this.wanInterfaces.includes(iface);
    if (!onWan) {
      event.kind = 'Observed';
      event.policyNote = 'Watchlist hit on an interface not configured as WAN. Set the WAN interface list to classify it.';
    }
    else if (this.exposedPorts[event.dport]) {
      event.kind = 'Exposed';
      event.policyLabel = this.exposedPorts[event.dport];
      event.policyNote = 'Hit matches a configured exposed service. The watchlist line alone does not confirm whether the forward accepted it.';
    }
    else {
      event.kind = 'Blocked';
      event.policyNote = 'WAN watchlist hit. Default-deny blocks this port unless an allow rule or port forward applies.';
    }
    return event;
  },

  loadPreferences: function() {
    try {
      this.showReputation = localStorage.getItem('reffix-log-viewer.external-reputation') === 'true';
      const presets = JSON.parse(localStorage.getItem('reffix-log-viewer.filters') || '[]');
      this.filterPresets = Array.isArray(presets) ? presets.filter(p =>
        p && typeof p.name === 'string' && typeof p.query === 'string' &&
        ['all', 'blocked', 'observed', 'allowed', 'exposed'].includes(p.kind) &&
        ['all', 'tcp', 'udp'].includes(p.proto) &&
        ['all', '5m', '15m', '1h', '6h', '24h'].includes(p.window)
      ).slice(0, 20) : [];
      this.historyRetention = ['off', '1', '7', '30'].includes(localStorage.getItem('reffix-log-viewer.history-days'))
        ? localStorage.getItem('reffix-log-viewer.history-days') : 'off';
    }
    catch (e) {
      this.showReputation = false;
      this.filterPresets = [];
      this.historyRetention = 'off';
    }
  },

  saveFilterPreset: function() {
    const name = prompt(_('Name this filter preset'));
    if (!name || !name.trim()) return;
    const preset = {
      name: name.trim().slice(0, 40),
      query: this.search.value || '',
      kind: this.kind.value,
      proto: this.proto.value,
      window: this.window.value
    };
    this.filterPresets = this.filterPresets.filter(p => p.name !== preset.name);
    this.filterPresets.unshift(preset);
    this.filterPresets = this.filterPresets.slice(0, 20);
    try {
      localStorage.setItem('reffix-log-viewer.filters', JSON.stringify(this.filterPresets));
      this.renderPresetOptions();
      this.presets.value = preset.name;
    }
    catch (e) {
      ui.addNotification(null, E('p', _('Unable to save filter presets in this browser.')), 'warning');
    }
  },

  renderPresetOptions: function() {
    if (!this.presets) return;
    this.presets.replaceChildren(E('option', {value: ''}, _('Saved filters')));
    this.filterPresets.forEach(p => this.presets.appendChild(E('option', {value: p.name}, p.name)));
  },

  applyFilterPreset: function(name) {
    const preset = this.filterPresets.find(p => p.name === name);
    if (!preset) return;
    this.search.value = preset.query;
    this.kind.value = this.kindFilter = preset.kind;
    this.proto.value = this.protoFilter = preset.proto;
    this.window.value = this.timeFilter = preset.window;
    this.maxEntries = PAGE_SIZE;
    this.renderRows();
    this.renderInsightsPanel();
  },

  removeFilterPreset: function() {
    const name = this.presets.value;
    if (!name) return;
    this.filterPresets = this.filterPresets.filter(p => p.name !== name);
    try {
      localStorage.setItem('reffix-log-viewer.filters', JSON.stringify(this.filterPresets));
    }
    catch (e) {}
    this.renderPresetOptions();
  },

  loadGeoStatus: async function() {
    try {
      this.geoStatus = JSON.parse(await fs.exec_direct('/usr/bin/flint4-geoip', ['--status'], 'text'));
    }
    catch (e) {
      this.geoStatus = {available: false};
    }
  },

  applyPolicy: function(event) {
    const marker = String(event.marker || event.prefix || '').toUpperCase();
    const rule = this.policyRules.find(p =>
      p && String(p.marker || '').toUpperCase() === marker &&
      (p.port == null || Number(p.port) === Number(event.dport))
    );
    if (rule) {
      event.policyLabel = String(rule.label || marker);
      event.policyNote = String(rule.note || '');
    }
    if (marker === 'INFRA_PORT_HIT' && /logging-only match|does not by itself block/i.test(event.policyNote || ''))
      event.policyNote = 'WAN watchlist hit. Default-deny blocks this port unless an allow rule or port forward applies.';
    event.baseKind = event.kind;
    event.basePolicyLabel = event.policyLabel;
    event.basePolicyNote = event.policyNote;
    return event;
  },

  routerNowMs: function() {
    return this.routerClockAtSync ? this.routerClockAtSync + (Date.now() - this.routerClockSyncedAt) : Date.now();
  },

  storeHistory: async function(events) {
    if (this.historyRetention === 'off' || !events.length) return;
    const db = await openHistoryDatabase();
    const tx = db.transaction('events', 'readwrite');
    const store = tx.objectStore('events');
    const now = this.routerNowMs();
    events.forEach(event => {
      if (event.rawLine) store.put({
        key: event.rawLine,
        rawLine: event.rawLine,
        timestampMs: event.timestampMs || now,
        routerOffset: this.watchConfig && this.watchConfig.router_offset || ''
      });
    });
    const cutoff = now - Number(this.historyRetention) * 86400000;
    let kept = 0;
    const cursorRequest = store.index('timestampMs').openCursor(null, 'prev');
    cursorRequest.onsuccess = () => {
      const cursor = cursorRequest.result;
      if (!cursor) return;
      if (cursor.value.timestampMs < cutoff || kept >= 10000) cursor.delete();
      else kept++;
      cursor.continue();
    };
    await historyTransactionDone(tx);
  },

  loadHistory: async function() {
    if (this.historyRetention === 'off') return [];
    const db = await openHistoryDatabase();
    const tx = db.transaction('events', 'readonly');
    const rows = await historyRequest(tx.objectStore('events').getAll());
    const cutoff = this.routerNowMs() - Number(this.historyRetention) * 86400000;
    return rows.filter(row => row.timestampMs >= cutoff).map((row, index) => {
      const event = parseLine(row.rawLine, index + 1, row.routerOffset);
      if (!event) return null;
      event.timestampMs = row.timestampMs;
      return this.applyTrafficContext(this.applyPolicy(event));
    }).filter(Boolean);
  },

  clearLocalHistory: async function() {
    const db = await openHistoryDatabase();
    const tx = db.transaction('events', 'readwrite');
    tx.objectStore('events').clear();
    await historyTransactionDone(tx);
    this.historyCache = new Map();
    this.historySeedPending = false;
    this.historyNeedsReload = true;
    this.historyStatusText.textContent = _('Browser-local history cleared.');
    this.historyRetentionSelect.value = this.historyRetention;
    this.refreshEvents().catch(() => {});
  },

  renderWatchStatus: function() {
    if (!this.watchStatusText) return;
    const config = this.watchConfig;
    if (!config) {
      this.watchStatusText.textContent = _('WAN watch status unavailable · IPv4 only');
      return;
    }
    const active = config.active_interface || _('WAN interface unresolved');
    const count = String(config.ports || '').split(/[\s,]+/).filter(Boolean).length;
    const state = config.enabled ? (config.installed ? _('active') : _('enabled · rules not detected')) : _('disabled');
    const rate = config.log_rate ? ' · ' + config.log_rate : '';
    this.watchStatusText.textContent = _('WAN watch ') + state + ' · IPv4 · ' + active + ' · ' + count + _(' ports') + rate;
  },

  exportSettings: async function() {
    await this.loadWatchConfig();
    const data = {
      schema: 'reffix-firewall-log-settings', version: 1,
      watcher: this.watchConfig ? {
        enabled: this.watchConfig.enabled !== false,
        wan_interface: this.watchConfig.wan_interface || 'auto',
        ports: this.watchConfig.ports || ''
      } : null,
      browser: {
        exposedPorts: this.exposedPorts,
        filterPresets: this.filterPresets,
        showReputation: this.showReputation,
        historyRetention: this.historyRetention,
        insightsOpen: !!this.insightsDisclosure.open
      }
    };
    downloadBlob('reffix-firewall-log-settings.json', new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'}));
  },

  importSettings: function(file) {
    const reader = new FileReader();
    reader.onerror = () => ui.addNotification(null, E('p', _('Could not read settings file.')), 'error');
    reader.onload = () => {
      let data;
      try { data = JSON.parse(String(reader.result || '')); }
      catch (e) { ui.addNotification(null, E('p', _('Settings file is not valid JSON.')), 'error'); return; }
      if (!data || data.schema !== 'reffix-firewall-log-settings' || data.version !== 1 || !data.browser || typeof data.browser !== 'object') {
        ui.addNotification(null, E('p', _('This is not a supported Firewall Log settings file.')), 'error'); return;
      }
      const browser = data.browser;
      const exposedPorts = {};
      if (browser.exposedPorts && typeof browser.exposedPorts === 'object' && !Array.isArray(browser.exposedPorts)) {
        for (const [port, label] of Object.entries(browser.exposedPorts)) {
          if (!/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535 || typeof label !== 'string' || label.length > 60) {
            ui.addNotification(null, E('p', _('Settings contain an invalid exposed port label.')), 'error'); return;
          }
          exposedPorts[port] = label.trim() || ('Port ' + port);
        }
      }
      const presets = Array.isArray(browser.filterPresets) ? browser.filterPresets.filter(p =>
        p && typeof p.name === 'string' && typeof p.query === 'string' &&
        ['all', 'blocked', 'observed', 'allowed', 'exposed'].includes(p.kind) &&
        ['all', 'tcp', 'udp'].includes(p.proto) && ['all', '5m', '15m', '1h', '6h', '24h'].includes(p.window)
      ).slice(0, 20) : [];
      const watcher = data.watcher;
      if (watcher && (typeof watcher.enabled !== 'boolean' || typeof watcher.wan_interface !== 'string' ||
          !/^(auto|[a-zA-Z0-9_.:-]{1,32})$/.test(watcher.wan_interface) || typeof watcher.ports !== 'string' ||
          watcher.ports.length > 4096 || /[^0-9,\s]/.test(watcher.ports))) {
        ui.addNotification(null, E('p', _('Settings contain invalid WAN watch configuration.')), 'error'); return;
      }
      const summary = E('ul', {}, [
        E('li', {}, Object.keys(exposedPorts).length + _(' exposed-service labels')),
        E('li', {}, presets.length + _(' saved filter presets')),
        E('li', {}, watcher ? _('Router WAN watch settings will also be updated.') : _('Router WAN watch settings are not included.'))
      ]);
      ui.showModal(_('Review settings import'), [
        E('p', {}, _('Review the settings before applying them. Router settings will be written to this router; browser preferences stay local to this browser.')),
        summary
      ], [
        E('button', {class: 'cbi-button', click: ui.hideModal}, _('Cancel')),
        E('button', {class: 'cbi-button cbi-button-action important', click: async () => {
          try {
            if (watcher) {
              const raw = await fs.exec_direct('/usr/sbin/infra-port-watch-config', ['set', watcher.enabled ? '1' : '0', watcher.wan_interface, watcher.ports], 'text');
              this.watchConfig = JSON.parse(raw || '{}');
              this.watchConfigLoaded = true;
            }
          }
          catch (e) { ui.addNotification(null, E('p', _('Router settings were not applied: ') + (e.message || e)), 'error'); return; }
          this.exposedPorts = exposedPorts;
          this.filterPresets = presets;
          this.showReputation = browser.showReputation === true;
          this.historyRetention = ['off', '1', '7', '30'].includes(browser.historyRetention) ? browser.historyRetention : 'off';
          try {
            localStorage.setItem('reffix-log-viewer.traffic-context', JSON.stringify({exposedPorts}));
            localStorage.setItem('reffix-log-viewer.filters', JSON.stringify(presets));
            localStorage.setItem('reffix-log-viewer.external-reputation', String(this.showReputation));
            localStorage.setItem('reffix-log-viewer.history-days', this.historyRetention);
            localStorage.setItem('reffix-log-viewer.insights-open', String(browser.insightsOpen === true));
          }
          catch (e) { ui.addNotification(null, E('p', _('Some browser settings could not be stored.')), 'warning'); }
          ui.hideModal();
          location.reload();
        }}, _('Apply settings'))
      ]);
    };
    reader.readAsText(file);
  },

  importFirewallForwards: async function() {
    await this.loadWatchConfig(true);
    const redirects = this.watchConfig && Array.isArray(this.watchConfig.redirects) ? this.watchConfig.redirects : [];
    if (!redirects.length) {
      ui.addNotification(null, E('p', _('No enabled IPv4 port forwards were found in the firewall configuration.')), 'info');
      return;
    }
    const choices = redirects.map((item, index) => {
      const portSpec = String(item.source_ports || '').trim();
      const tokens = portSpec.split(/[\s,]+/).filter(Boolean);
      const ports = [];
      let valid = tokens.length > 0;
      tokens.forEach(token => {
        const match = token.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
        if (!match) { valid = false; return; }
        const from = Number(match[1]), to = Number(match[2] || match[1]);
        if (!from || to < from || to > 65535 || ports.length + to - from + 1 > 256) { valid = false; return; }
        for (let port = from; port <= to; port++) ports.push(port);
      });
      const check = E('input', {type: 'checkbox', disabled: !valid, checked: valid});
      const protocol = item.protocol || 'tcp';
      return {item, ports, check, label: E('label', {class: 'fw-settings-field'}, [check,
        E('span', {}, (item.name || _('Unnamed forward')) + ' · ' + (item.source_zone || '?') + ' · ' + portSpec + '/' + protocol +
          (item.destination_port ? ' → destination port ' + item.destination_port : ''))])};
    });
    ui.showModal(_('Review firewall forwards'), [
      E('p', {class: 'cbi-section-descr'}, _('Select which WAN-forward destination ports should receive exposed-service labels. This imports labels only; it does not read LAN hostnames or change firewall rules. Verify each entry before importing.')),
      ...choices.map(choice => choice.label)
    ], [
      E('button', {class: 'cbi-button', click: ui.hideModal}, _('Cancel')),
      E('button', {class: 'cbi-button cbi-button-action important', click: () => {
        const next = Object.assign({}, this.exposedPorts);
        choices.filter(choice => choice.check.checked).forEach(({item, ports}) => {
          const label = String(item.name || 'Exposed service').slice(0, 60);
          ports.forEach(port => { next[Number(port)] = label; });
        });
        this.exposedPorts = next;
        try { localStorage.setItem('reffix-log-viewer.traffic-context', JSON.stringify({exposedPorts: next})); }
        catch (e) { ui.addNotification(null, E('p', _('Could not save labels in this browser.')), 'warning'); }
        this.events.forEach(event => this.applyTrafficContext(event));
        this.historyNeedsReload = true;
        ui.hideModal();
        this.renderRows();
        this.renderInsightsPanel();
      }}, _('Import selected labels'))
    ]);
  },

  parseTrafficContext: function(interfacesText, portsText) {
    const interfaces = [...new Set(String(interfacesText || '').split(/[\s,]+/)
      .map(v => v.trim().toLowerCase()).filter(v => /^[a-z0-9_.:-]{1,32}$/.test(v)))];
    const ports = {};
    String(portsText || '').split(/\r?\n/).forEach(line => {
      const match = line.match(/^\s*(\d{1,5})\s*(?:=|:|\s)\s*(.*?)\s*$/);
      if (!match) return;
      const port = Number(match[1]);
      if (port > 0 && port <= 65535) ports[port] = match[2].slice(0, 60) || ('Port ' + port);
    });
    return {interfaces, ports};
  },

  openTrafficSettings: async function() {
    await this.loadWatchConfig();
    const interfaces = E('input', {class: 'cbi-input-text', type: 'text', placeholder: _('auto or e.g. eth2')});
    interfaces.value = this.watchConfig ? this.watchConfig.wan_interface : 'auto';
    const watching = E('input', {type: 'checkbox'});
    watching.checked = !this.watchConfig || this.watchConfig.enabled !== false;
    const watchPorts = E('textarea', {class: 'cbi-input-text', rows: 7, placeholder: _('Comma or whitespace separated ports')});
    watchPorts.value = this.watchConfig ? this.watchConfig.ports : '';
    const ports = E('textarea', {class: 'cbi-input-text', rows: 6, placeholder: _('8096 = Jellyfin\n8920 = Jellyfin HTTPS')});
    ports.value = Object.entries(this.exposedPorts).map(([port, label]) => port + ' = ' + label).join('\n');
    ui.showModal(_('WAN interface and exposed services'), [
      E('p', {class: 'cbi-section-descr'}, _('The watch rule logs matching TCP SYN and UDP probes only; it never accepts or drops traffic. Auto resolves the logical WAN device. Watch settings are saved on this router; service labels below are saved in this browser.')),
      E('label', {class: 'fw-settings-field fw-watch-toggle'}, [watching, E('span', {}, _('Enable WAN port watch'))]),
      E('label', {class: 'fw-settings-field'}, [E('span', {}, _('WAN interface (auto or device name shown in IN=)')), interfaces]),
      E('label', {class: 'fw-settings-field'}, [E('span', {}, _('Ports to log (1–65535; comma or whitespace separated; up to 256)')), watchPorts]),
      E('label', {class: 'fw-settings-field'}, [E('span', {}, _('Exposed destination ports (one port = label per line)')), ports]),
      E('div', {class: 'right'}, [
        E('button', {class: 'cbi-button', click: ui.hideModal}, _('Cancel')),
        E('button', {class: 'cbi-button cbi-button-action important', click: async () => {
          const wan = interfaces.value.trim() || 'auto';
          try {
            const raw = await fs.exec_direct('/usr/sbin/infra-port-watch-config', [
              'set', watching.checked ? '1' : '0', wan, watchPorts.value
            ], 'text');
            this.watchConfig = JSON.parse(raw || '{}');
            this.watchConfigLoaded = true;
          }
          catch (e) {
            ui.addNotification(null, E('p', _('Could not apply WAN watch settings: ') + (e.message || e)), 'error');
            return;
          }
          const config = this.parseTrafficContext(interfaces.value, ports.value);
          const activeInterface = this.watchConfig.active_interface ||
            (this.watchConfig.wan_interface !== 'auto' ? this.watchConfig.wan_interface : '');
          this.wanInterfaces = activeInterface ? [String(activeInterface).toLowerCase()] : [];
          this.exposedPorts = config.ports;
          try { localStorage.setItem('reffix-log-viewer.traffic-context', JSON.stringify({exposedPorts: config.ports})); }
          catch (e) { ui.addNotification(null, E('p', _('Could not save settings in this browser.')), 'warning'); }
          this.events.forEach(event => this.applyTrafficContext(event));
          this.historyNeedsReload = true;
          ui.hideModal();
          this.renderRows();
          this.renderInsightsPanel();
        }}, _('Save settings'))
      ])
    ]);
  },

  getTimeWindowMs: function() {
    return ({
      '5m': 5 * 60 * 1000,
      '15m': 15 * 60 * 1000,
      '1h': 60 * 60 * 1000,
      '6h': 6 * 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000
    })[this.timeFilter] || 0;
  },

  renderInsights: function(events) {
    const sources = new Map();
    const ports = new Map();
    const asns = new Map();

    events.forEach(e => {
      if (e.source) {
        if (!sources.has(e.source))
          sources.set(e.source, { source: e.source, count: 0, ports: new Set(), firstMs: e.timestampMs, lastMs: e.timestampMs, first: e.timestamp, last: e.timestamp });
        const s = sources.get(e.source);
        s.count++;
        if (e.dport) s.ports.add(e.dport);
        if (e.timestampMs && (!s.lastMs || e.timestampMs > s.lastMs)) {
          s.lastMs = e.timestampMs;
          s.last = e.timestamp;
        }
        if (e.timestampMs && (!s.firstMs || e.timestampMs < s.firstMs)) {
          s.firstMs = e.timestampMs;
          s.first = e.timestamp;
        }
      }

      if (e.dport) {
        const key = String(e.dport);
        if (!ports.has(key))
          ports.set(key, { port: e.dport, service: e.service, count: 0, tcp: 0, udp: 0 });
        const p = ports.get(key);
        p.count++;
        if (e.protocol === 'TCP') p.tcp++;
        if (e.protocol === 'UDP') p.udp++;
      }

      const geo = this.geoCache[e.source] || {};
      if (geo.asn_organization) {
        const key = geo.asn_organization;
        if (!asns.has(key)) asns.set(key, { name: key, count: 0, sources: new Set() });
        asns.get(key).count++;
        asns.get(key).sources.add(e.source);
      }
    });

    const top = (map, key, limit) => [...map.values()]
      .sort((a, b) => b.count - a.count || String(a[key]).localeCompare(String(b[key])))
      .slice(0, limit);
    const renderList = (items, render, empty) => items.length
      ? '<ul class="fw-insight-list">' + items.map(render).join('') + '</ul>'
      : '<p class="fw-muted">' + empty + '</p>';

    const topSources = renderList(top(sources, 'source', 5), item => {
      const geo = this.geoCache[item.source] || {};
      const label = geo.country_name || 'GeoIP pending';
      const countryCode = (geo.country_code || '').toUpperCase();
      const asn = geo.asn_organization ? ' · ' + geo.asn_organization : '';
      const firstSeen = item.firstMs ? new Date(item.firstMs).toLocaleString() : item.first;
      const lastSeen = item.lastMs ? new Date(item.lastMs).toLocaleString() : item.last;
      return '<li><button type="button" class="fw-insight-filter" data-source-filter="' + esc(item.source) + '"><span class="fw-insight-ip"><span class="fw-flag" title="' + esc(label) + '">' + countryFlag(countryCode) + '</span><code>' + esc(item.source) + '</code></span><span>' + item.count + ' events</span>' +
        '<small>' + esc(label + asn) + ' · ' + item.ports.size + ' ports</small><small>First ' + esc(firstSeen) + ' · Last ' + esc(lastSeen) + '</small></button></li>';
    }, 'No sources in this window.');

    const sortedPorts = [...ports.values()].sort((a, b) => b.count - a.count || a.port - b.port);
    const visiblePorts = this.showAllPorts ? sortedPorts : sortedPorts.slice(0, 5);
    const topPorts = renderList(visiblePorts, item =>
      '<li><button type="button" class="fw-insight-port" data-port-filter="' + item.port + '"><strong>' + esc(item.port) + ' · ' + esc(item.service) + '</strong><span>' + item.count + ' events</span>' +
      '<small>TCP ' + item.tcp + ' · UDP ' + item.udp + '</small></button></li>',
      'No destination ports in this window.');

    const topAsns = renderList(top(asns, 'name', 5), item =>
      '<li><strong>' + esc(item.name) + '</strong><span>' + item.count + ' events</span>' +
      '<small>' + item.sources.size + ' source IPs · based on local GeoIP matches</small></li>',
      'No ASN data yet. GeoIP enrichment currently checks up to 60 unique recent sources.');

    const timelineEvents = events.filter(event => Number.isFinite(event.timestampMs));
    const latestTime = this.routerNowMs();
    const earliestTime = timelineEvents.length ? Math.min(...timelineEvents.map(event => event.timestampMs)) : latestTime;
    const span = this.getTimeWindowMs() || Math.max(60000, latestTime - earliestTime + 30000);
    const bucketMs = Math.max(30000, Math.ceil(span / 24 / 30000) * 30000);
    const timelineEnd = Math.ceil(latestTime / bucketMs) * bucketMs;
    const timelineStart = timelineEnd - bucketMs * 24;
    const buckets = Array.from({length:24}, () => 0);
    timelineEvents.forEach(event => {
      const index = Math.floor((event.timestampMs - timelineStart) / bucketMs);
      if (index >= 0 && index < buckets.length) buckets[index]++;
    });
    const maxBucket = Math.max(1, ...buckets);
    const timelineHtml = '<div class="fw-timeline" role="group" aria-label="' + esc(_('Firewall events by time; select a bar to filter')) + '">' +
      buckets.map((count, index) => {
        const start = timelineStart + index * bucketMs;
        const end = start + bucketMs;
        const label = new Date(start).toLocaleString() + ' · ' + count + _(' events');
        const selected = this.timelineRange && this.timelineRange.start === start ? ' aria-pressed="true"' : ' aria-pressed="false"';
        const height = Math.max(count ? 7 : 2, Math.round(count / maxBucket * 100));
        return '<button type="button" class="fw-timeline-bin' + (count ? '' : ' empty') + '" style="--fw-bar-height:' + height + '%" data-timeline-start="' + start + '" data-timeline-end="' + end + '" title="' + esc(label) + '" aria-label="' + esc(label) + '"' + selected + '><span>' + (count || '') + '</span></button>';
      }).join('') + '</div><div class="fw-timeline-labels"><span>' + esc(new Date(timelineStart).toLocaleTimeString()) + '</span><span>' + esc(new Date(timelineEnd).toLocaleTimeString()) + '</span></div>';

    const scanMap = new Map();
    events.forEach(e => {
      if (!isPublic(e.source)) return;
      if (!scanMap.has(e.source))
        scanMap.set(e.source, { source: e.source, count: 0, ports: new Set(), destinations: new Set(), blocked: 0 });
      const s = scanMap.get(e.source);
      s.count++;
      if (e.dport) s.ports.add(e.dport);
      if (e.destination) s.destinations.add(e.destination);
      if (e.kind === 'Blocked') s.blocked++;
    });
    const signals = [...scanMap.values()].map(s => {
      const multiPort = s.ports.size >= 8;
      const burst = s.count >= 25;
      return Object.assign(s, {
        multiPort: multiPort,
        burst: burst,
        signal: multiPort && burst ? 'Multi-port + burst' :
          multiPort ? 'Multi-port pattern' : 'High-volume burst'
      });
    }).filter(s => s.multiPort || s.burst)
      .sort((a, b) => (b.ports.size * 2 + b.count) - (a.ports.size * 2 + a.count))
      .slice(0, 6);

    const scanHtml = renderList(signals, item => {
      const geo = this.geoCache[item.source] || {};
      const country = geo.country_name || 'GeoIP pending';
      const countryCode = (geo.country_code || '').toUpperCase();
      const details = item.ports.size + ' ports · ' + item.destinations.size + ' targets · ' +
        item.count + ' events';
      return '<li><button type="button" class="fw-insight-filter fw-scan-filter" data-source-filter="' + esc(item.source) + '"><span class="fw-insight-ip"><span class="fw-flag" title="' + esc(country) + '">' + countryFlag(countryCode) + '</span><code>' + esc(item.source) + '</code></span><span class="fw-signal">' + esc(item.signal) + '</span>' +
        '<small>' + esc(details) + ' · ' + esc(country) + '</small></button></li>';
    }, 'No scan/burst thresholds triggered in this window.');

    const policyNotes = this.policyRules.length
      ? 'Local policy labels active: ' + this.policyRules.length
      : 'Optional policy labels: copy the example config to /etc/log-viewer/policies.json and edit it for your rules.';
    return '<div class="fw-insight fw-insight-timeline"><h3>Activity timeline</h3>' + timelineHtml +
        (this.timelineRange ? '<button type="button" class="cbi-button fw-clear-timeline">' + _('Clear timeline filter') + '</button>' : '<p class="fw-muted">' + _('Select a time bar to filter the event table.') + '</p>') + '</div>' +
      '<div class="fw-insight"><h3>Top sources</h3>' + topSources + '</div>' +
      '<div class="fw-insight"><h3>Destination ports <small>(' + sortedPorts.length + ' total)</small></h3>' + topPorts +
        (sortedPorts.length > 5 ? '<button type="button" class="cbi-button fw-show-all-ports">' + (this.showAllPorts ? _('Show top five') : _('Show all ports')) + '</button>' : '') + '</div>' +
      '<div class="fw-insight"><h3>Top ASNs</h3>' + topAsns + '</div>' +
      '<div class="fw-insight"><h3>Scan / burst signals</h3><p class="fw-muted">Heuristic only: 8+ ports or 25+ events from one public source.</p>' + scanHtml + '</div>' +
      '<div class="fw-insight fw-insight-policy"><h3>Policy context</h3><p class="fw-muted">' + esc(policyNotes) + '</p>' +
      '<p class="fw-muted">WAN watchlist hits are shown as Blocked under the default-deny policy. Explicit allow and port-forward rules can create exceptions; Allowed appears only when an allow rule logs it.</p></div>';
  },



  lookupGeo: async function(ip) {
    if (!isPublic(ip)) return {};
    if (Object.prototype.hasOwnProperty.call(this.geoCache, ip) &&
        (Object.keys(this.geoCache[ip]).length || Date.now() - (this.geoCacheAt[ip] || 0) < 5 * 60 * 1000))
      return this.geoCache[ip];
    if (this.geoLookupInFlight.has(ip)) return this.geoLookupInFlight.get(ip);
    const lookup = (async () => {
      try {
        const raw = await fs.exec_direct('/usr/bin/flint4-geoip', ['--json', ip], 'text');
        const data = JSON.parse(raw || '{}');
        this.geoCache[ip] = data.error ? {} : data;
        this.geoCacheAt[ip] = Date.now();
        return this.geoCache[ip];
      }
      catch (e) {
        this.geoCache[ip] = {};
        this.geoCacheAt[ip] = Date.now();
        return {};
      }
      finally {
        this.geoLookupInFlight.delete(ip);
      }
    })();
    this.geoLookupInFlight.set(ip, lookup);
    return lookup;
  },

  enrich: async function(events) {
    const addresses = [...new Set(events.map(e => e.source).filter(isPublic))].slice(0, 60);
    for (let i = 0; i < addresses.length; i += 6)
      await Promise.all(addresses.slice(i, i + 6).map(ip => this.lookupGeo(ip)));
  },

  refreshEvents: async function() {
    const generation = ++this.refreshGeneration;
    await this.loadPolicyRules();
    await this.loadWatchConfig(true);
    this.loadTrafficContext();
    const raw = await this.getLogData();
    if (generation !== this.refreshGeneration) return;
    const text = raw || '';
    this.sourceLineCount = text ? text.split('\n').filter(Boolean).length : 0;
    this.lastCollectedAt = Date.now();
    const changed = text !== this.lastRawData;
    if (changed) {
      this.lastRawData = text;
      const lines = text.trim() ? text.trim().split('\n') : [];
      this.liveEvents = lines.map((line, i) => parseLine(line, i + 1, this.watchConfig && this.watchConfig.router_offset))
        .filter(Boolean).map(e => this.applyTrafficContext(this.applyPolicy(e))).slice(-MAX_LINES).reverse();
      const previousKeys = this.liveEventKeys || new Set();
      this.newLiveEvents = this.liveEvents.filter(event => !previousKeys.has(event.rawLine));
      this.liveEventKeys = new Set(this.liveEvents.map(event => event.rawLine));
      this.historyNeedsReload = true;
    }
    this.liveEvents.forEach(event => this.applyTrafficContext(event));
    if (this.historyRetention !== 'off' && (changed || this.historyNeedsReload)) {
      try {
        const historyDelta = changed ? this.newLiveEvents : (this.historySeedPending ? this.liveEvents : []);
        await this.storeHistory(historyDelta);
        this.historySeedPending = false;
        if (!this.historyCache || this.historyNeedsReload) {
          const historical = await this.loadHistory();
          this.historyCache = new Map(historical.map(event => [event.rawLine, event]));
        }
        else if (changed) {
          this.newLiveEvents.forEach(event => this.historyCache.set(event.rawLine, event));
        }
        const cutoff = this.routerNowMs() - Number(this.historyRetention) * 86400000;
        const historical = [...this.historyCache.values()]
          .filter(event => event.timestampMs >= cutoff)
          .sort((a, b) => (b.timestampMs || 0) - (a.timestampMs || 0))
          .slice(0, 10000);
        this.historyCache = new Map(historical.map(event => [event.rawLine, event]));
        const merged = new Map();
        historical.concat(this.liveEvents).forEach((event, index) => {
          event.id = index + 1;
          merged.set(event.rawLine, event);
        });
        this.events = [...merged.values()].sort((a, b) => (b.timestampMs || 0) - (a.timestampMs || 0)).slice(0, 10000);
        this.historyStatusText.textContent = _('Browser-local history: ') + this.historyCache.size + _(' stored events · max 10,000');
        this.historyNeedsReload = false;
      }
      catch (error) {
        this.events = this.liveEvents;
        this.historyStatusText.textContent = _('Browser-local history unavailable: ') + (error.message || error);
      }
    }
    else this.events = this.liveEvents;
    if (this.historyRetention === 'off') this.historyStatusText.textContent = _('Browser-local history is off · router buffer only');
    this.statusText.textContent = this.paused
      ? _('Auto-refresh paused · manually refreshed at ') + (new Date()).toLocaleTimeString()
      : _('Live · updated ') + (new Date()).toLocaleTimeString();
    this.logStatus.textContent = _('Read ') + this.sourceLineCount + _(' of up to ') + this.logReadLimit +
      _(' most recent source lines · source limit · collected ') + new Date(this.lastCollectedAt).toLocaleString();
    this.renderWatchStatus();
    if (changed) {
      this.renderRows();
      this.renderInsightsPanel();
      // Draw the log immediately. GeoIP is checked before starting lookups so a missing database
      // does not spawn a failed mmdblookup process for every address on every refresh.
    }
    if (!this.geoStatusCheckedAt || Date.now() - this.geoStatusCheckedAt > 5 * 60 * 1000) {
      this.geoStatusCheckedAt = Date.now();
      this.loadGeoStatus().then(() => {
        if (generation !== this.refreshGeneration) return;
        this.renderGeoStatus();
        if (changed && this.geoStatus && this.geoStatus.available) this.enrichAndRender();
      });
    }
    else if (changed && this.geoStatus && this.geoStatus.available) this.enrichAndRender();
  },

  enrichAndRender: function() {
    if (!this.tbody || !this.tbody.isConnected) return;
    const generation = this.refreshGeneration;
    this.enrich(this.events.slice(0, 60)).then(() => {
      if (generation !== this.refreshGeneration || !this.tbody || !this.tbody.isConnected) return;
      this.renderRows();
      this.renderInsightsPanel();
    });
  },

  getWindowedEvents: function() {
    let events = this.getTimeFilteredEvents();
    if (this.timelineRange)
      events = events.filter(event => event.timestampMs >= this.timelineRange.start && event.timestampMs < this.timelineRange.end);
    return events;
  },

  getTimeFilteredEvents: function() {
    const windowMs = this.getTimeWindowMs();
    const now = this.routerNowMs();
    return this.events.filter(e => {
      if (!windowMs || !e.timestampMs) return true;
      const age = now - e.timestampMs;
      return age >= -60000 && age <= windowMs;
    });
  },

  getMatchingEvents: function(windowed) {
    const query = (this.search.value || '').toLowerCase();
    return (windowed || this.getWindowedEvents()).filter(e => {
      const geo = this.geoCache[e.source] || {};
      const searchable = [
        e.timestamp, e.kind, e.source, e.destination, e.dport, e.service,
        e.protocol, e.prefix, e.marker, e.policyLabel, e.policyNote,
        geo.country_name, geo.country_code, geo.asn_organization
      ].join(' ').toLowerCase();
      return (this.kindFilter === 'all' || e.kind.toLowerCase() === this.kindFilter) &&
        (this.protoFilter === 'all' || e.protocol.toLowerCase() === this.protoFilter) &&
        (!this.sourceFilter || e.source === this.sourceFilter) &&
        (this.portFilter == null || Number(e.dport) === Number(this.portFilter)) &&
        searchable.includes(query);
    });
  },

  renderEventRow: function(e) {
    const geo = this.geoCache[e.source] || {};
    const countryCode = (geo.country_code || '').toUpperCase();
    const country = geo.country_name || 'GeoIP unavailable';
    const asn = geo.asn_organization || '';
    const kindClass = e.kind === 'Blocked' ? 'blocked' : (e.kind === 'Allowed' ? 'allowed' : (e.kind === 'Exposed' ? 'exposed' : 'observed'));
    const policyText = e.policyLabel || e.marker || e.prefix;
    const title = [e.marker || e.prefix, e.policyNote].filter(Boolean).join(' · ');
    return '<tr class="tr fw-' + kindClass + '" data-event-id="' + esc(e.id) + '">' +
      '<td class="td fw-time">' + esc(e.timestamp) + '</td>' +
      '<td class="td fw-source"><span class="fw-flag" title="' + esc(country) + '">' + countryFlag(countryCode) + '</span> ' +
        '<code>' + esc(e.source) + '</code>' +
        '<small>' + esc(country) + (asn ? ' · ' + esc(asn) : '') + '</small></td>' +
      '<td class="td"><code>' + esc(e.destination || '—') + '</code></td>' +
      '<td class="td fw-port"><strong>' + esc(e.dport || '—') + '</strong><small>' + esc(e.service) + ' · ' + esc(e.protocol) + '</small></td>' +
      '<td class="td"><span class="fw-badge ' + kindClass + '" title="' + esc(title) + '">' + esc(e.kind) + '</span><small class="fw-event-policy">' + esc(policyText || '—') + '</small></td>' +
      '<td class="td fw-detail">SPT ' + esc(e.sport || '—') + ' · ' + esc(e.flags || '—') +
        '<small>' + esc(e.iface || '—') + (e.ttl ? ' · TTL ' + esc(e.ttl) : '') + '</small></td>' +
      '<td class="td"><button type="button" class="cbi-button fw-event-details" data-id="' + esc(e.id) + '">' + esc(_('Details')) + '</button>' +
        (this.showReputation ? '<a class="fw-reputation" href="https://www.abuseipdb.com/check/' + encodeURIComponent(e.source) +
          '" target="_blank" rel="noreferrer" title="' + esc(_('Opens AbuseIPDB and shares this source IP with that service')) + '">' + esc(_('AbuseIPDB ↗')) + '</a>' : '') + '</td></tr>';
  },

  renderInsightsPanel: function() {
    if (this.insights) this.insights.innerHTML = this.renderInsights(this.getTimeFilteredEvents());
  },

  renderGeoStatus: function() {
    if (!this.geoStatusText) return;
    if (!this.geoStatus || !this.geoStatus.available) {
      this.geoStatusText.textContent = _('GeoIP unavailable · country and ASN details hidden');
      return;
    }
    const age = this.geoStatus.age_days == null ? _('age unknown') : this.geoStatus.age_days + _(' days old');
    this.geoStatusText.textContent = _('Local GeoIP databases · oldest ') + age +
      (this.geoStatus.stale ? _(' · update recommended') : '');
  },

  renderRows: function() {
    if (!this.tbody) return;
    const windowed = this.getWindowedEvents();
    const matching = this.getMatchingEvents(windowed);
    this.filteredEvents = matching;
    const events = matching.slice(0, this.maxEntries);
    let blocked = 0, allowed = 0, exposed = 0;
    matching.forEach(e => {
      if (e.kind === 'Blocked') blocked++;
      else if (e.kind === 'Allowed') allowed++;
      else if (e.kind === 'Exposed') exposed++;
    });
    this.stats.innerHTML = [
      ['MATCHING EVENTS', matching.length],
      ['BLOCKED', blocked],
      ['EXPOSED SERVICE HITS', exposed],
      ['ALLOWED · EXPLICIT LOGS', allowed]
    ].map(function(item) {
      return '<div class="fw-stat"><span>' + item[0] + '</span><strong>' + item[1] + '</strong></div>';
    }).join('');

    this.tbody.innerHTML = events.map(event => this.renderEventRow(event)).join('') ||
      '<tr><td colspan="7" class="center">No matching firewall events in the selected window.</td></tr>';
    this.counter.textContent = _('Showing ') + events.length + _(' of ') + matching.length + _(' matching events · ') +
      windowed.length + _(' in selected window · ') + this.events.length + _(' loaded');
    this.loadMoreButton.hidden = events.length >= matching.length;
    this.loadMoreButton.textContent = _('Show ') + PAGE_SIZE + _(' more events · ') + (matching.length - events.length) + _(' remaining');
  },

  render: function() {
    this.loadPreferences();
    if (!document.getElementById('reffix-firewall-log-style')) document.head.appendChild(E('style', { id: 'reffix-firewall-log-style', type: 'text/css' }, `
      .fw-shell {
        --mp-bg: #2D2A2E;
        --mp-panel: #221F22;
        --mp-surface: #343136;
        --mp-hover: #403E41;
        --mp-border: #514D52;
        --mp-fg: #FCFCFA;
        --mp-muted: #C7C3C8;
        --mp-yellow: #FFD866;
        --mp-orange: #FC9867;
        --mp-pink: #FF6188;
        --mp-green: #A9DC76;
        --mp-cyan: #78DCE8;
        --mp-purple: #AB9DF2;
        box-sizing: border-box;
        width: 100%;
        min-width: 0;
        padding: 16px;
        color: var(--mp-fg) !important;
        background: var(--mp-bg) !important;
        border: 1px solid var(--mp-border);
        border-radius: 12px;
        font-size: 14px;
        line-height: 1.5;
        color-scheme: dark;
      }
      .fw-shell * { box-sizing: border-box; }
      .fw-shell .fw-description {
        color: var(--mp-muted) !important;
        font-size: 13px !important;
        line-height: 1.6 !important;
        font-weight: 500;
        margin: 0 0 14px;
        max-width: 110ch;
      }
      .fw-shell .fw-stats {
        display: grid;
        grid-template-columns: repeat(6, minmax(0, 1fr));
        gap: 10px;
        margin: 14px 0;
      }
      .fw-shell .fw-stat {
        min-width: 0;
        padding: 13px 14px;
        background: var(--mp-panel) !important;
        border: 1px solid var(--mp-border) !important;
        border-radius: 9px;
      }
      .fw-shell .fw-stat span {
        display: block;
        color: var(--mp-muted) !important;
        font-size: 11px !important;
        font-weight: 800;
        line-height: 1.35;
        letter-spacing: .06em;
        opacity: 1 !important;
      }
      .fw-shell .fw-stat strong {
        display: block;
        margin-top: 4px;
        color: var(--mp-fg) !important;
        font-size: 27px !important;
        font-weight: 850;
        line-height: 1.25;
        font-variant-numeric: tabular-nums;
      }
      .fw-shell .fw-stat:nth-child(1) strong { color: var(--mp-cyan) !important; }
      .fw-shell .fw-stat:nth-child(2) strong { color: var(--mp-pink) !important; }
      .fw-shell .fw-stat:nth-child(3) strong { color: var(--mp-cyan) !important; }
      .fw-shell .fw-stat:nth-child(4) strong { color: var(--mp-green) !important; }

      .fw-shell .fw-toolbar {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 8px;
        margin: 12px 0;
        color: var(--mp-muted) !important;
        font-size: 13px !important;
      }
      .fw-shell .fw-toolbar input,
      .fw-shell .fw-toolbar select {
        min-width: 145px;
        min-height: 38px !important;
        padding: 7px 10px !important;
        color: var(--mp-fg) !important;
        background: var(--mp-surface) !important;
        border: 1px solid var(--mp-border) !important;
        border-radius: 7px !important;
        box-shadow: none !important;
        font-size: 13px !important;
      }
      .fw-shell .fw-toolbar input::placeholder { color: #B0AAB2 !important; opacity: 1; }
      .fw-shell .fw-toolbar input:focus,
      .fw-shell .fw-toolbar select:focus {
        border-color: var(--mp-yellow) !important;
        outline: 2px solid rgba(255,216,102,.22);
        outline-offset: 1px;
      }
      .fw-shell .fw-toolbar button {
        min-height: 38px !important;
        padding: 7px 12px !important;
        color: var(--mp-fg) !important;
        background: var(--mp-hover) !important;
        border: 1px solid #625B65 !important;
        border-radius: 7px !important;
        font-size: 13px !important;
        font-weight: 700;
        transition: background .12s ease, border-color .12s ease;
      }
      .fw-shell .fw-toolbar button:hover {
        background: #4A454C !important;
        border-color: var(--mp-purple) !important;
      }
      .fw-shell .fw-toolbar .cbi-button-action {
        color: #221F22 !important;
        background: var(--mp-yellow) !important;
        border-color: var(--mp-yellow) !important;
        font-weight: 850;
      }
      .fw-shell .fw-toolbar .cbi-button-action:hover {
        background: #FFE59A !important;
      }
      .fw-shell .fw-toolbar .right {
        color: var(--mp-muted) !important;
        font-size: 12px !important;
        font-variant-numeric: tabular-nums;
      }
      .fw-shell .fw-muted {
        color: var(--mp-muted) !important;
        font-size: 12px !important;
        line-height: 1.55 !important;
        opacity: 1 !important;
      }

      .fw-shell .fw-insights {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 10px;
        margin: 12px 0 16px;
      }
      .fw-shell .fw-insight {
        min-width: 0;
        padding: 14px !important;
        color: var(--mp-fg) !important;
        background: var(--mp-panel) !important;
        border: 1px solid var(--mp-border) !important;
        border-radius: 10px !important;
      }
      .fw-shell .fw-insight h3 {
        margin: 0 0 10px !important;
        color: var(--mp-fg) !important;
        font-size: 15px !important;
        font-weight: 850 !important;
        line-height: 1.35;
        letter-spacing: .01em;
      }
      .fw-shell .fw-insight:nth-child(1) h3 { color: var(--mp-cyan) !important; }
      .fw-shell .fw-insight:nth-child(2) h3 { color: var(--mp-orange) !important; }
      .fw-shell .fw-insight:nth-child(3) h3 { color: var(--mp-purple) !important; }
      .fw-shell .fw-insight:nth-child(4) h3 { color: var(--mp-yellow) !important; }
      .fw-shell .fw-insight-list { list-style: none; margin: 0; padding: 0; }
      .fw-shell .fw-insight-list li {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        gap: 4px 10px;
        padding: 8px 0 !important;
        color: var(--mp-fg) !important;
        border-bottom: 1px solid #413C43 !important;
        font-size: 13px !important;
        line-height: 1.45 !important;
      }
      .fw-shell .fw-insight-list li:last-child { border-bottom: 0 !important; }
      .fw-shell .fw-insight-list li > button {
        display: grid; grid-column: 1 / -1; grid-template-columns: minmax(0, 1fr) auto;
        width: 100%; gap: 4px 10px; padding: 0; color: inherit; text-align: left;
        background: transparent; border: 0; cursor: pointer;
      }
      .fw-shell .fw-insight-list li > button:hover code { border-color: var(--mp-cyan); }
      .fw-shell .fw-insight-port { grid-column: 1 / -1 !important; }
      .fw-shell .fw-insights-disclosure > summary { cursor: pointer; font-weight: 800; padding: 8px 2px; }
      .fw-shell .fw-timeline { height: 96px; display: grid; grid-template-columns: repeat(24, minmax(0, 1fr)); align-items: end; gap: 3px; margin: 12px 0 4px; }
      .fw-shell .fw-timeline-bin { min-width: 0; height: var(--fw-bar-height); min-height: 4px; padding: 0; color: var(--mp-bg); background: var(--mp-cyan); border: 1px solid transparent; border-radius: 3px 3px 0 0; cursor: pointer; }
      .fw-shell .fw-timeline-bin.empty { background: var(--mp-surface); border-color: var(--mp-border); }
      .fw-shell .fw-timeline-bin[aria-pressed="true"] { background: var(--mp-yellow); border-color: var(--mp-fg); }
      .fw-shell .fw-timeline-bin span { display: block; overflow: hidden; color: var(--mp-bg); font-size: 9px; line-height: 1; }
      .fw-shell .fw-timeline-labels { display: flex; justify-content: space-between; color: var(--mp-muted); font-size: 11px; }
      .fw-shell .fw-insight-timeline { grid-column: 1 / -1; }
      .fw-shell .fw-settings-field { display: grid; gap: 6px; margin: 12px 0; font-weight: 700; }
      .fw-shell .fw-watch-toggle { display: flex; align-items: center; gap: 8px; }
      .fw-shell .fw-settings-field textarea { resize: vertical; }
      .fw-shell .fw-badge.exposed { color: #20232D !important; background: #78DCE8 !important; border-color: #A8EFF5 !important; }
      .fw-shell .fw-insight-ip { display: flex; min-width: 0; align-items: center; gap: 5px; }
      .fw-shell .fw-insight-ip code { overflow-wrap: anywhere; }
      .fw-shell .fw-insight-list li span {
        color: var(--mp-fg) !important;
        font-size: 12px !important;
        font-weight: 750;
        white-space: nowrap;
      }
      .fw-shell .fw-insight-list li small {
        grid-column: 1 / -1;
        color: var(--mp-muted) !important;
        font-size: 12px !important;
        font-weight: 500;
        line-height: 1.5 !important;
        opacity: 1 !important;
        overflow-wrap: anywhere;
      }
      .fw-shell .fw-insight-list code,
      .fw-shell .fw-source code,
      .fw-shell .fw-table code {
        color: var(--mp-fg) !important;
        background: var(--mp-surface) !important;
        border: 1px solid #49434B;
        border-radius: 4px;
        padding: 2px 5px;
        font-size: 12px !important;
        font-weight: 700;
      }
      .fw-shell .fw-signal {
        padding: 3px 7px !important;
        color: #FFE8B3 !important;
        background: #51412A !important;
        border: 1px solid #8C7040 !important;
        border-radius: 5px;
        font-size: 11px !important;
        font-weight: 850;
        white-space: nowrap;
      }
      .fw-shell .fw-insight-policy { grid-column: 1 / -1; }
      .fw-shell .fw-status-row { display: flex; flex-wrap: wrap; gap: 6px 18px; color: var(--mp-muted); font-size: 12px; }
      .fw-shell .fw-file-import { position: relative; display: inline-flex; align-items: center; min-height: 38px; padding: 7px 12px; color: var(--mp-fg); background: var(--mp-hover); border: 1px solid #625B65; border-radius: 7px; cursor: pointer; }
      .fw-shell .fw-file-import input { position: absolute; inset: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; }
      .fw-shell .fw-file-import:focus-within { outline: 2px solid var(--mp-purple); outline-offset: 2px; }
      .fw-shell .fw-history-toolbar { align-items: center; }
      .fw-shell .fw-history-control { display: inline-flex; align-items: center; gap: 8px; }
      .fw-shell .fw-privacy { display: flex; align-items: flex-start; gap: 8px; margin: 8px 0; color: var(--mp-muted); font-size: 12px; }
      .fw-shell .fw-privacy input { margin-top: 3px; }
      .fw-shell .fw-load-more { display: block; width: 100%; margin-top: 10px; }
      .fw-shell .fw-event-details { margin-right: 8px; }
      .fw-shell .fw-reputation { display: inline-block; margin-top: 8px; }
      .fw-event-meta { display: grid; grid-template-columns: minmax(100px, auto) minmax(0, 1fr); gap: 6px 12px; }
      .fw-event-meta dt { font-weight: 700; }
      .fw-event-meta dd { margin: 0; overflow-wrap: anywhere; }
      .fw-raw-log { max-height: 30vh; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
      .fw-shell .fw-event-policy {
        display: block;
        max-width: 18em;
        margin-top: 3px;
        color: var(--mp-muted) !important;
        font-size: 11px !important;
        line-height: 1.45;
        opacity: 1 !important;
        overflow-wrap: anywhere;
      }

      .fw-shell .fw-tablewrap {
        max-height: 68vh;
        overflow: auto;
        background: var(--mp-panel) !important;
        border: 1px solid var(--mp-border) !important;
        border-radius: 10px !important;
      }
      .fw-shell .fw-table {
        width: 100%;
        min-width: 1000px;
        border-collapse: separate;
        border-spacing: 0;
        background: var(--mp-bg) !important;
        font-size: 13px !important;
      }
      .fw-shell .fw-table thead th {
        position: sticky;
        top: 0;
        z-index: 2;
        padding: 11px 10px !important;
        color: var(--mp-fg) !important;
        background: #403A42 !important;
        border-bottom: 1px solid #645A67 !important;
        font-size: 12px !important;
        font-weight: 850 !important;
        line-height: 1.4;
        text-align: left;
      }
      .fw-shell .fw-table tbody tr { background: #302C32 !important; }
      .fw-shell .fw-table tbody tr:nth-child(even) { background: #29262B !important; }
      .fw-shell .fw-table tbody tr:hover { background: #403B43 !important; }
      .fw-shell .fw-table tbody tr.fw-blocked { box-shadow: inset 3px 0 var(--mp-pink); }
      .fw-shell .fw-table tbody tr.fw-observed { box-shadow: inset 3px 0 var(--mp-yellow); }
      .fw-shell .fw-table tbody tr.fw-allowed { box-shadow: inset 3px 0 var(--mp-green); }
      .fw-shell .fw-table tbody tr.fw-exposed { box-shadow: inset 3px 0 var(--mp-cyan); }
      .fw-shell .fw-table td {
        padding: 10px !important;
        color: var(--mp-fg) !important;
        border-bottom: 1px solid #443E46 !important;
        font-size: 13px !important;
        font-weight: 500;
        line-height: 1.5 !important;
        vertical-align: top;
      }
      .fw-shell .fw-time {
        min-width: 130px;
        color: #E3DDE5 !important;
        font-size: 12px !important;
        white-space: nowrap;
      }
      .fw-shell .fw-source { min-width: 190px; }
      .fw-shell .fw-source code {
        color: #FFFFFF !important;
        font-size: 13px !important;
        font-weight: 800;
        white-space: nowrap;
      }
      .fw-shell .fw-source small,
      .fw-shell .fw-detail small,
      .fw-shell .fw-table td:nth-child(4) small {
        display: block;
        margin-top: 4px;
        color: var(--mp-muted) !important;
        font-size: 12px !important;
        font-weight: 500;
        line-height: 1.5 !important;
        opacity: 1 !important;
      }
      .fw-shell .fw-table td:nth-child(3) code {
        color: var(--mp-cyan) !important;
        white-space: nowrap;
        display: inline-block;
      }
      .fw-shell .fw-table td:nth-child(3) { white-space: nowrap; }
      .fw-shell .fw-table td:nth-child(4) strong { color: var(--mp-orange) !important; font-size: 14px; }
      .fw-shell .fw-table a {
        color: var(--mp-cyan) !important;
        font-weight: 750;
        text-decoration: none;
      }
      .fw-shell .fw-table a:hover { color: #B8F3F8 !important; text-decoration: underline; }
      .fw-shell .fw-badge {
        display: inline-block;
        padding: 4px 8px !important;
        border: 1px solid transparent;
        border-radius: 5px !important;
        font-size: 12px !important;
        font-weight: 850 !important;
        line-height: 1.35;
        white-space: nowrap;
      }
      .fw-shell .fw-badge.observed {
        color: #2D2A2E !important;
        background: var(--mp-yellow) !important;
        border-color: #FFE69A !important;
      }
      .fw-shell .fw-badge.blocked,
      .fw-shell .fw-badge.danger {
        color: #2D2A2E !important;
        background: var(--mp-pink) !important;
        border-color: #FFA0B8 !important;
      }
      .fw-shell .fw-badge.allowed {
        color: #22251E !important;
        background: var(--mp-green) !important;
        border-color: #C5EBA1 !important;
      }
      .fw-shell .fw-flag { display: inline-flex; min-width: 22px; height: 16px; margin-right: 4px; align-items: center; justify-content: center; vertical-align: middle; }
      .fw-shell .fw-flag-img { display: block; width: 20px; max-height: 15px; height: auto; object-fit: contain; border: 1px solid #514D52; border-radius: 2px; }
      .fw-shell .fw-flag-fallback { font-size: 1.1em; line-height: 1; }
      .fw-shell :focus-visible {
        outline: 2px solid var(--mp-purple) !important;
        outline-offset: 2px;
      }
      .fw-shell .fw-description { font-size: 15px !important; line-height: 1.6 !important; }
      .fw-shell .fw-stats { grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
      .fw-shell .fw-stat span { font-size: 13px !important; }
      .fw-shell .fw-stat strong { font-size: 28px !important; }
      .fw-shell .fw-primary-toolbar { align-items: stretch; gap: 10px; margin: 14px 0 8px; }
      .fw-shell .fw-primary-toolbar input,
      .fw-shell .fw-primary-toolbar select { min-height: 44px; font-size: 15px !important; }
      .fw-shell .fw-primary-toolbar input { flex: 2 1 240px; }
      .fw-shell .fw-primary-toolbar select { flex: 1 1 145px; }
      .fw-shell .fw-primary-toolbar button,
      .fw-shell .fw-secondary-toolbar button,
      .fw-shell .fw-history-toolbar button,
      .fw-shell .fw-file-import { min-height: 42px !important; padding: 9px 14px !important; font-size: 14px !important; }
      .fw-shell .fw-results-meta { display: flex; flex-wrap: wrap; gap: 5px 16px; margin: 8px 0 12px; color: var(--mp-muted); font-size: 14px !important; line-height: 1.5; }
      .fw-shell .fw-results-meta .right { color: var(--mp-fg) !important; font-size: 14px !important; }
      .fw-shell .fw-more-actions { margin: 12px 0; border: 1px solid var(--mp-border); border-radius: 8px; background: var(--mp-panel); }
      .fw-shell .fw-more-actions > summary { padding: 12px 14px; cursor: pointer; font-size: 15px; font-weight: 750; }
      .fw-shell .fw-more-content { display: grid; gap: 10px; padding: 0 14px 14px; }
      .fw-shell .fw-secondary-toolbar { gap: 8px; }
      .fw-shell .fw-secondary-toolbar select { min-width: 190px; min-height: 42px; font-size: 14px !important; }
      .fw-shell .fw-status-row,
      .fw-shell .fw-history-toolbar,
      .fw-shell .fw-privacy { font-size: 14px !important; line-height: 1.5; }
      .fw-shell .fw-history-control select { min-height: 42px; font-size: 14px !important; }
      .fw-shell .fw-insights-disclosure > summary { font-size: 15px; }
      .fw-shell .fw-table { min-width: 960px; font-size: 15px !important; }
      .fw-shell .fw-table thead th { padding: 13px 12px !important; font-size: 14px !important; }
      .fw-shell .fw-table td { padding: 13px 12px !important; font-size: 15px !important; line-height: 1.55 !important; }
      .fw-shell .fw-time { min-width: 150px; font-size: 14px !important; }
      .fw-shell .fw-source { min-width: 210px; }
      .fw-shell .fw-source code { font-size: 14px !important; }
      .fw-shell .fw-source small,
      .fw-shell .fw-detail small,
      .fw-shell .fw-table td:nth-child(4) small { font-size: 13px !important; }
      .fw-shell .fw-table code { font-size: 14px !important; }
      .fw-shell .fw-event-policy { font-size: 13px !important; }
      .fw-shell .fw-badge { padding: 5px 9px !important; font-size: 14px !important; }
      .fw-shell .fw-event-details { min-height: 38px !important; padding: 7px 12px !important; font-size: 14px !important; }
      .fw-shell .fw-load-more { min-height: 44px !important; margin-top: 12px; font-size: 15px !important; }
      @media (max-width: 1200px) {
        .fw-shell .fw-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      }
      @media (max-width: 800px) {
        .fw-shell { padding: 10px; }
        .fw-shell .fw-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .fw-shell .fw-insights { grid-template-columns: 1fr; }
        .fw-shell .fw-insight-policy { grid-column: auto; }
        .fw-shell .fw-toolbar input,
        .fw-shell .fw-toolbar select { flex: 1 1 140px; min-width: 0; }
      }
    `));

    this.stats = E('div', {class: 'fw-stats'});
    this.search = E('input', {class: 'cbi-input-text', type: 'search', placeholder: _('Search IP, country, ASN, port or service…'), 'aria-label': _('Search firewall events')});
    this.kind = E('select', {class: 'cbi-input-select', 'aria-label': _('Filter by verdict')}, [
      E('option', {value: 'all'}, _('All verdict types')),
      E('option', {value: 'blocked'}, _('Blocked only')),
      E('option', {value: 'exposed'}, _('Exposed service hits')),
      E('option', {value: 'observed'}, _('Other interface / unclassified')),
      E('option', {value: 'allowed'}, _('Allowed · explicit logs only'))
    ]);
    this.proto = E('select', {class: 'cbi-input-select', 'aria-label': _('Filter by protocol')}, [
      E('option', {value: 'all'}, _('All protocols')),
      E('option', {value: 'tcp'}, 'TCP'),
      E('option', {value: 'udp'}, 'UDP')
    ]);
    this.window = E('select', {class: 'cbi-input-select', title: _('Filter events by log timestamp'), 'aria-label': _('Filter by time window')}, [
      E('option', {value: 'all'}, _('All loaded')),
      E('option', {value: '5m'}, _('Last 5 minutes')),
      E('option', {value: '15m'}, _('Last 15 minutes')),
      E('option', {value: '1h'}, _('Last hour')),
      E('option', {value: '6h'}, _('Last 6 hours')),
      E('option', {value: '24h'}, _('Last 24 hours'))
    ]);
    this.presets = E('select', {class: 'cbi-input-select', title: _('Browser-local saved filter presets'), 'aria-label': _('Saved filter presets')});
    this.renderPresetOptions();
    this.counter = E('span', {class: 'right'});
    this.statusText = E('span', {class: 'fw-muted'});
    this.logStatus = E('span', {class: 'fw-muted'});
    this.geoStatusText = E('span', {class: 'fw-muted'});
    this.watchStatusText = E('span', {class: 'fw-muted'});
    this.historyStatusText = E('span', {class: 'fw-muted'});
    this.historyRetentionSelect = E('select', {class: 'cbi-input-select', 'aria-label': _('Browser-local history retention')}, [
      E('option', {value: 'off'}, _('Live buffer only')),
      E('option', {value: '1'}, _('Keep 24 hours locally')),
      E('option', {value: '7'}, _('Keep 7 days locally')),
      E('option', {value: '30'}, _('Keep 30 days locally'))
    ]);
    this.historyRetentionSelect.value = this.historyRetention;
    this.reputationCheckbox = E('input', {type: 'checkbox', change: ev => {
        this.showReputation = ev.target.checked;
        try { localStorage.setItem('reffix-log-viewer.external-reputation', String(this.showReputation)); } catch (e) {}
        this.renderRows();
      }});
    this.reputationCheckbox.checked = this.showReputation;
    this.reputationToggle = E('label', {class: 'fw-privacy'}, [
      this.reputationCheckbox,
      E('span', {}, _('Show AbuseIPDB links (opening one shares its source IP with that service)'))
    ]);
    this.loadMoreButton = E('button', {class: 'cbi-button fw-load-more', hidden: true, click: () => {
      this.maxEntries += PAGE_SIZE;
      this.renderRows();
    }}, _('Show ') + PAGE_SIZE + _(' more events'));
    this.pauseButton = E('button', {class: 'cbi-button fw-pause-button', click: () => {
      this.paused = !this.paused;
      this.pauseButton.textContent = this.paused ? _('Resume live') : _('Pause live');
      this.statusText.textContent = this.paused ? _('Auto-refresh paused') : _('Auto-refresh every 15s');
    }}, _('Pause live'));
    this.tbody = E('tbody');
    this.insights = E('div', {class: 'fw-insights'});
    this.insightsDisclosure = E('details', {class: 'fw-insights-disclosure'}, [
      E('summary', {}, _('Insights · sources, ports, ASNs and scan patterns')),
      this.insights
    ]);
    try { this.insightsDisclosure.open = localStorage.getItem('reffix-log-viewer.insights-open') === 'true'; } catch (e) {}

    const table = E('table', {class: 'table fw-table'}, [
      E('thead', {}, E('tr', {class: 'tr table-titles'},
        ['Time', 'Source / GeoIP', 'Destination', 'Port / Protocol', 'Verdict', 'Packet', 'Details']
          .map(t => E('th', {class: 'th'}, _(t))))),
      this.tbody
    ]);

    const advancedActions = E('details', {class: 'fw-more-actions'}, [
      E('summary', {}, _('More options')),
      E('div', {class: 'fw-more-content'}, [
        E('div', {class: 'fw-toolbar fw-secondary-toolbar'}, [
          this.presets,
          E('button', {class: 'cbi-button', click: () => this.saveFilterPreset()}, _('Save filter')),
          E('button', {class: 'cbi-button', click: () => this.removeFilterPreset()}, _('Delete saved filter')),
          E('button', {class: 'cbi-button', click: () => this.exportCSV(true)}, _('Export all loaded')),
          E('button', {class: 'cbi-button', click: () => this.openTrafficSettings()}, _('WAN / exposed ports')),
          E('button', {class: 'cbi-button', click: () => this.importFirewallForwards()}, _('Import firewall forwards')),
          E('button', {class: 'cbi-button', click: () => this.exportSettings()}, _('Export settings')),
          E('label', {class: 'fw-file-import'}, [E('span', {}, _('Import settings')), this.settingsFile = E('input', {type: 'file', accept: 'application/json,.json', 'aria-label': _('Import Firewall Log settings file'), change: ev => {
            const file = ev.target.files && ev.target.files[0];
            if (file) this.importSettings(file);
            ev.target.value = '';
          }})]),
          E('button', {class: 'cbi-button', click: () => {
            this.sourceFilter = ''; this.portFilter = null; this.timelineRange = null; this.renderRows(); this.renderInsightsPanel();
          }}, _('Clear insight filters'))
        ]),
        E('div', {class: 'fw-toolbar fw-history-toolbar'}, [
          E('label', {class: 'fw-history-control'}, [E('span', {}, _('Browser-local history')), this.historyRetentionSelect]),
          E('button', {class: 'cbi-button', click: () => this.clearLocalHistory().catch(e => ui.addNotification(null, E('p', e.message), 'error'))}, _('Clear local history')),
          E('span', {class: 'fw-muted'}, _('Stored in this browser only · max 10,000 events'))
        ]),
        E('div', {class: 'fw-status-row'}, [this.logStatus, this.watchStatusText, this.geoStatusText, this.historyStatusText]),
        this.reputationToggle
      ])
    ]);

    const result = E('div', {class: 'fw-shell'}, [
      E('p', {class: 'cbi-section-descr fw-description'}, _('Each row is one firewall event. WAN watchlist hits are Blocked unless the destination has an exposed-service label. Allowed requires an explicit ALLOW/ACCEPT log. GeoIP lookups stay local.')),
      this.stats,
      E('div', {class: 'fw-toolbar fw-primary-toolbar'}, [
        this.search, this.kind, this.proto, this.window,
        E('button', {class: 'cbi-button cbi-button-action', click: () => this.refreshEvents().catch(e => ui.addNotification(null, E('p', e.message), 'error'))}, _('Refresh')),
        this.pauseButton,
        E('button', {class: 'cbi-button cbi-button-action fw-export-button', click: () => this.exportCSV(false)}, _('Export filtered CSV'))
      ]),
      E('div', {class: 'fw-results-meta'}, [this.counter, this.statusText]),
      this.insightsDisclosure,
      E('div', {class: 'fw-tablewrap'}, table),
      this.loadMoreButton,
      advancedActions
    ]);

    this.tbody.addEventListener('click', ev => {
      const detailButton = ev.target.closest('.fw-event-details');
      if (detailButton) {
        const event = this.events.find(item => String(item.id) === detailButton.getAttribute('data-id'));
        if (event) this.showEventDetails(event);
      }
    });
    this.insights.addEventListener('click', ev => {
      const timelineButton = ev.target.closest('.fw-timeline-bin');
      if (timelineButton) {
        const start = Number(timelineButton.getAttribute('data-timeline-start'));
        this.timelineRange = {start, end: Number(timelineButton.getAttribute('data-timeline-end'))};
        this.maxEntries = PAGE_SIZE;
        this.renderRows();
        this.renderInsightsPanel();
        return;
      }
      if (ev.target.closest('.fw-clear-timeline')) {
        this.timelineRange = null;
        this.maxEntries = PAGE_SIZE;
        this.renderRows();
        this.renderInsightsPanel();
        return;
      }
      const portButton = ev.target.closest('.fw-insight-port');
      const sourceButton = ev.target.closest('.fw-insight-filter');
      if (portButton) {
        this.portFilter = Number(portButton.getAttribute('data-port-filter'));
        this.sourceFilter = '';
      }
      else if (sourceButton) {
        this.sourceFilter = sourceButton.getAttribute('data-source-filter') || '';
        this.portFilter = null;
      }
      else {
        const allPorts = ev.target.closest('.fw-show-all-ports');
        if (!allPorts) return;
        this.showAllPorts = !this.showAllPorts;
        this.renderInsightsPanel();
        return;
      }
      this.search.value = '';
      this.maxEntries = PAGE_SIZE;
      this.renderRows();
      this.insightsDisclosure.open = false;
    });
    this.insightsDisclosure.addEventListener('toggle', () => {
      try { localStorage.setItem('reffix-log-viewer.insights-open', String(this.insightsDisclosure.open)); } catch (e) {}
    });
    this.search.addEventListener('input', () => {
      clearTimeout(this.searchTimer);
      this.searchTimer = setTimeout(() => {
        this.maxEntries = PAGE_SIZE;
        this.renderRows();
      }, 120);
    });
    this.kind.addEventListener('change', () => { this.kindFilter = this.kind.value; this.maxEntries = PAGE_SIZE; this.renderRows(); });
    this.proto.addEventListener('change', () => { this.protoFilter = this.proto.value; this.maxEntries = PAGE_SIZE; this.renderRows(); });
    this.window.addEventListener('change', () => {
      this.timeFilter = this.window.value;
      this.timelineRange = null;
      this.maxEntries = PAGE_SIZE;
      this.renderRows();
      this.renderInsightsPanel();
    });
    this.presets.addEventListener('change', () => this.applyFilterPreset(this.presets.value));
    this.historyRetentionSelect.addEventListener('change', () => {
      const wasDisabled = this.historyRetention === 'off';
      this.historyRetention = this.historyRetentionSelect.value;
      this.historyNeedsReload = true;
      this.historySeedPending = wasDisabled && this.historyRetention !== 'off';
      try { localStorage.setItem('reffix-log-viewer.history-days', this.historyRetention); }
      catch (e) { this.historyStatusText.textContent = _('Browser storage is unavailable.'); }
      this.refreshEvents().catch(e => { this.historyStatusText.textContent = _('History update failed: ') + (e.message || e); });
    });
    this.statusText.textContent = _('Auto-refresh every 15s');
    this.refreshEvents().catch(e => ui.addNotification(null, E('p', _('Unable to load firewall events: ') + e.message), 'error'));
    this.timer = setInterval(() => {
      if (!this.paused && document.visibilityState === 'visible')
        this.refreshEvents().catch(() => {});
    }, 15000);
    return result;
  },

  showEventDetails: function(event) {
    const geo = this.geoCache[event.source] || {};
    const rows = [
      ['Time', event.timestamp], ['Verdict', event.kind], ['Source IP', event.source],
      ['Country', geo.country_name || 'GeoIP unavailable'], ['ASN', geo.asn_organization || '—'],
      ['Destination IP', event.destination], ['Protocol', event.protocol],
      ['Source port', event.sport], ['Destination port', event.dport], ['Service', event.service],
      ['Interface', event.iface], ['TTL', event.ttl], ['Flags', event.flags],
      ['Log marker', event.marker], ['Event prefix', event.prefix],
      ['Policy label', event.policyLabel], ['Policy note', event.policyNote]
    ];
    ui.showModal(_('Firewall event details'), [
      E('dl', {class: 'fw-event-meta'}, rows.flatMap(row => [
        E('dt', {}, _(row[0])), E('dd', {}, String(row[1] == null || row[1] === '' ? '—' : row[1]))
      ])),
      E('h3', {}, _('Original log line')),
      E('pre', {class: 'fw-raw-log'}, event.rawLine || '')
    ], [E('button', {class: 'cbi-button cbi-button-action important', click: ui.hideModal}, _('Close'))]);
  },

  exportCSV: function(allLoaded) {
    const rows = [['Time','Source IP','Country','ASN','Destination IP','Destination Port','Service','Protocol','Verdict','Log Marker','Policy Label','Policy Note','Source Port','Interface']];
    const events = allLoaded ? this.events : this.getMatchingEvents();
    events.forEach(e => {
      const geo = this.geoCache[e.source] || {};
      rows.push([e.timestamp,e.source,geo.country_name || '',geo.asn_organization || '',e.destination,e.dport,e.service,e.protocol,e.kind,e.marker || e.prefix,e.policyLabel || '',e.policyNote || '',e.sport,e.iface]);
    });
    const csv = rows.map(r => r.map(csvCell).join(',')).join('\r\n');
    downloadBlob(allLoaded ? 'firewall-log-all-loaded.csv' : 'firewall-log-filtered.csv',
      new Blob([csv], {type: 'text/csv;charset=utf-8'}));
  },

  remove: function() {
    if (this.timer) clearInterval(this.timer);
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.refreshGeneration++;
    this.tbody = null;
    this.insights = null;
  }
});
