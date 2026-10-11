'use strict';
'require view';
'require fs';
'require ui';

const MAX_LINES = 1500;
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

function isPublic(ip) {
  if (!ip || ip === '-' || ip === '0.0.0.0') return false;
  if (ip.indexOf(':') >= 0) {
    const s = ip.toLowerCase();
    return !(s === '::' || s === '::1' || s.startsWith('fc') ||
      s.startsWith('fd') || s.startsWith('fe8') || s.startsWith('fe9') ||
      s.startsWith('fea') || s.startsWith('feb'));
  }
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

function parseLine(line, index) {
  const observed = line.includes('INFRA_PORT_HIT:');
  const hasPacketTuple = /SRC=\S+.*DPT=\d+/.test(line);
  const blockMarker = /\b(?:DROP|REJECT)\b/i.test(line) ||
    /(?:^|[\s:])[A-Z0-9_-]*(?:BLOCKED|BLOCK|DROP|REJECT):/i.test(line);
  const allowMarker =
    /(?:^|[\s:])[A-Z0-9_-]*(?:ALLOWED|ALLOW|ACCEPTED|ACCEPT|PASSED|PASS):/i.test(line);
  const markerMatch = line.match(/(?:^|\s)([A-Z][A-Z0-9_-]{1,39}):/);
  const marker = markerMatch ? markerMatch[1] : '';

  let prefix = '';
  let kind = '';
  if (observed) {
    prefix = 'INFRA_PORT_HIT';
    kind = 'Observed';
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
  const timestampMs = timestamp ? Date.parse(timestamp) : NaN;

  return {
    id: index,
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

return view.extend({
  viewName: 'firewall',
  title: _('Firewall Log'),
  events: [],
  geoCache: {},
  kindFilter: 'all',
  protoFilter: 'all',
  timeFilter: 'all',
  paused: false,
  policyRules: [],
  policyRulesLoaded: false,
  maxEntries: 500,

  getLogData: function() {
    // Fetch a bounded tail and filter in JavaScript. The -e regex syntax in
    // OpenWrt logread is not consistently extended regex, so alternation like
    // (INFRA_PORT_HIT|DROP|REJECT) can match nothing on valid router builds.
    return fs.exec_direct('/sbin/logread', ['-l', String(MAX_LINES)], 'text')
      .catch(function() {
        return fs.exec_direct('/usr/sbin/logread', ['-l', String(MAX_LINES)], 'text');
      });
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
    return event;
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
          sources.set(e.source, { source: e.source, count: 0, ports: new Set(), last: e.timestamp });
        const s = sources.get(e.source);
        s.count++;
        if (e.dport) s.ports.add(e.dport);
        if (e.timestampMs && (!s.lastMs || e.timestampMs > s.lastMs)) {
          s.lastMs = e.timestampMs;
          s.last = e.timestamp;
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
      const asn = geo.asn_organization ? ' · ' + geo.asn_organization : '';
      return '<li><code>' + esc(item.source) + '</code><span>' + item.count + ' events</span>' +
        '<small>' + esc(label + asn) + ' · ' + item.ports.size + ' ports</small></li>';
    }, 'No sources in this window.');

    const topPorts = renderList(top(ports, 'port', 5), item =>
      '<li><strong>' + esc(item.port) + ' · ' + esc(item.service) + '</strong><span>' + item.count + ' events</span>' +
      '<small>TCP ' + item.tcp + ' · UDP ' + item.udp + '</small></li>',
      'No destination ports in this window.');

    const topAsns = renderList(top(asns, 'name', 5), item =>
      '<li><strong>' + esc(item.name) + '</strong><span>' + item.count + ' events</span>' +
      '<small>' + item.sources.size + ' source IPs · based on local GeoIP matches</small></li>',
      'No ASN data yet. GeoIP enrichment currently checks up to 60 unique recent sources.');

    const scanMap = new Map();
    events.forEach(e => {
      if (!isPublic(e.source)) return;
      if (!scanMap.has(e.source))
        scanMap.set(e.source, { source: e.source, count: 0, ports: new Set(), destinations: new Set(), blocked: 0, observed: 0 });
      const s = scanMap.get(e.source);
      s.count++;
      if (e.dport) s.ports.add(e.dport);
      if (e.destination) s.destinations.add(e.destination);
      if (e.kind === 'Blocked') s.blocked++;
      if (e.kind === 'Observed') s.observed++;
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
      const details = item.ports.size + ' ports · ' + item.destinations.size + ' targets · ' +
        item.count + ' events';
      return '<li><code>' + esc(item.source) + '</code><span class="fw-signal">' + esc(item.signal) + '</span>' +
        '<small>' + esc(details) + ' · ' + esc(geo.country_name || 'GeoIP pending') + '</small></li>';
    }, 'No scan/burst thresholds triggered in this window.');

    const policyNotes = this.policyRules.length
      ? 'Local policy labels active: ' + this.policyRules.length
      : 'Optional policy labels: copy the example config to /etc/log-viewer/policies.json and edit it for your rules.';
    return '<div class="fw-insight"><h3>Top sources</h3>' + topSources + '</div>' +
      '<div class="fw-insight"><h3>Top destination ports</h3>' + topPorts + '</div>' +
      '<div class="fw-insight"><h3>Top ASNs</h3>' + topAsns + '</div>' +
      '<div class="fw-insight"><h3>Scan / burst signals</h3><p class="fw-muted">Heuristic only: 8+ ports or 25+ events from one public source.</p>' + scanHtml + '</div>' +
      '<div class="fw-insight fw-insight-policy"><h3>Policy context</h3><p class="fw-muted">' + esc(policyNotes) + '</p>' +
      '<p class="fw-muted">Observed ≠ allowed. Blocked and Allowed require explicit log evidence; default-deny policy cannot be inferred from silence.</p></div>';
  },



  lookupGeo: async function(ip) {
    if (!isPublic(ip)) return {};
    if (Object.prototype.hasOwnProperty.call(this.geoCache, ip)) return this.geoCache[ip];
    try {
      const raw = await fs.exec_direct('/usr/bin/flint4-geoip', ['--json', ip], 'text');
      const data = JSON.parse(raw || '{}');
      this.geoCache[ip] = data;
      return data;
    }
    catch (e) {
      this.geoCache[ip] = {};
      return {};
    }
  },

  enrich: async function(events) {
    const addresses = [...new Set(events.map(e => e.source).filter(isPublic))].slice(0, 60);
    for (let i = 0; i < addresses.length; i += 6)
      await Promise.all(addresses.slice(i, i + 6).map(ip => this.lookupGeo(ip)));
  },

  refreshEvents: async function() {
    await this.loadPolicyRules();
    const raw = await this.getLogData();
    const lines = (raw || '').trim().split('\n');
    this.events = lines.map((line, i) => parseLine(line, i + 1))
      .filter(Boolean).map(e => this.applyPolicy(e)).slice(-MAX_LINES).reverse();
    await this.enrich(this.events.slice(0, 60));
    this.statusText.textContent = this.paused
      ? _('Auto-refresh paused · manually refreshed at ') + (new Date()).toLocaleTimeString()
      : _('Live · updated ') + (new Date()).toLocaleTimeString();
    this.renderRows();
  },

  renderRows: function() {
    if (!this.tbody) return;
    const query = (this.search.value || '').toLowerCase();
    const windowMs = this.getTimeWindowMs();
    const now = Date.now();
    const windowed = this.events.filter(e => {
      if (!windowMs || !e.timestampMs) return true;
      const age = now - e.timestampMs;
      return age >= -60000 && age <= windowMs;
    });
    const matching = windowed.filter(e => {
      const geo = this.geoCache[e.source] || {};
      const searchable = [
        e.timestamp, e.kind, e.source, e.destination, e.dport, e.service,
        e.protocol, e.prefix, e.marker, e.policyLabel, e.policyNote,
        geo.country_name, geo.country_code, geo.asn_organization
      ].join(' ').toLowerCase();
      return (this.kindFilter === 'all' || e.kind.toLowerCase() === this.kindFilter) &&
        (this.protoFilter === 'all' || e.protocol.toLowerCase() === this.protoFilter) &&
        searchable.includes(query);
    });
    const events = matching.slice(0, this.maxEntries);
    const blocked = matching.filter(e => e.kind === 'Blocked').length;
    const observed = matching.filter(e => e.kind === 'Observed').length;
    const allowed = matching.filter(e => e.kind === 'Allowed').length;
    const uniqueSources = new Set(matching.map(e => e.source).filter(Boolean)).size;
    const countries = new Set(matching.map(e => (this.geoCache[e.source] || {}).country_code).filter(Boolean)).size;
    this.stats.innerHTML = [
      ['MATCHING EVENTS', matching.length],
      ['UNIQUE SOURCES', uniqueSources],
      ['BLOCKED', blocked],
      ['OBSERVED · VERDICT UNKNOWN', observed],
      ['ALLOWED · EXPLICIT LOGS', allowed],
      ['COUNTRIES', countries]
    ].map(function(item) {
      return '<div class="fw-stat"><span>' + item[0] + '</span><strong>' + item[1] + '</strong></div>';
    }).join('');

    this.tbody.innerHTML = events.map(e => {
      const geo = this.geoCache[e.source] || {};
      const countryCode = (geo.country_code || '').toUpperCase();
      const country = geo.country_name || 'GeoIP unavailable';
      const asn = geo.asn_organization || '';
      const kindClass = e.kind === 'Blocked' ? 'blocked' : (e.kind === 'Allowed' ? 'allowed' : 'observed');
      const policyText = e.policyLabel || e.marker || e.prefix;
      const title = [e.marker || e.prefix, e.policyNote].filter(Boolean).join(' · ');
      return '<tr class="tr fw-' + kindClass + '">' +
        '<td class="td fw-time">' + esc(e.timestamp) + '</td>' +
        '<td class="td fw-source"><span class="fw-flag" title="' + esc(country) + '">' + countryFlag(countryCode) + '</span> ' +
          '<code>' + esc(e.source) + '</code> <button type="button" class="cbi-button fw-copy-ip" data-ip="' + esc(e.source) + '" title="Copy source IP">Copy</button>' +
          '<small>' + esc(country) + (asn ? ' · ' + esc(asn) : '') + '</small></td>' +
        '<td class="td"><code>' + esc(e.destination || '—') + '</code></td>' +
        '<td class="td"><strong>' + esc(e.dport || '—') + '</strong><small>' + esc(e.service) + '</small></td>' +
        '<td class="td">' + esc(e.protocol) + '</td>' +
        '<td class="td"><span class="fw-badge ' + kindClass + '" title="' + esc(title) + '">' + esc(e.kind) + '</span><small class="fw-event-policy">' + esc(policyText || '—') + '</small></td>' +
        '<td class="td fw-detail">SPT ' + esc(e.sport || '—') + ' · ' + esc(e.flags || '—') +
          '<small>' + esc(e.iface || '—') + (e.ttl ? ' · TTL ' + esc(e.ttl) : '') + (e.policyNote ? ' · ' + esc(e.policyNote) : '') + '</small></td>' +
        '<td class="td"><a href="https://www.abuseipdb.com/check/' + encodeURIComponent(e.source) +
          '" target="_blank" rel="noreferrer">Reputation ↗</a></td></tr>';
    }).join('') || '<tr><td colspan="8" class="center">No matching events in the selected window. Only explicitly logged DROP/REJECT/BLOCK and ALLOW/ACCEPT markers can prove a verdict.</td></tr>';
    this.counter.textContent = events.length + ' shown · ' + matching.length + ' matched · ' + windowed.length + ' in window · ' + this.events.length + ' loaded';
    if (this.insights) this.insights.innerHTML = this.renderInsights(windowed);
  },

  render: function() {
    document.head.appendChild(E('style', { type: 'text/css' }, `
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
      .fw-shell .fw-stat:nth-child(2) strong { color: var(--mp-purple) !important; }
      .fw-shell .fw-stat:nth-child(3) strong { color: var(--mp-pink) !important; }
      .fw-shell .fw-stat:nth-child(4) strong { color: var(--mp-yellow) !important; }
      .fw-shell .fw-stat:nth-child(5) strong { color: var(--mp-green) !important; }
      .fw-shell .fw-stat:nth-child(6) strong { color: var(--mp-orange) !important; }

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
      .fw-shell .fw-copy-ip {
        min-height: 25px !important;
        margin-left: 4px;
        padding: 2px 7px !important;
        color: var(--mp-cyan) !important;
        background: #2D3940 !important;
        border: 1px solid #53666B !important;
        border-radius: 5px !important;
        font-size: 11px !important;
        font-weight: 750;
      }
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
      .fw-shell .fw-copy-ip:focus-visible,
      .fw-shell .fw-toolbar button:focus-visible,
      .fw-shell a:focus-visible {
        outline: 2px solid var(--mp-purple) !important;
        outline-offset: 2px;
      }
      @media (max-width: 1200px) {
        .fw-shell .fw-stats { grid-template-columns: repeat(3, minmax(0, 1fr)); }
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
    this.search = E('input', {class: 'cbi-input-text', type: 'search', placeholder: _('Search IP, country, ASN, port or service…')});
    this.kind = E('select', {class: 'cbi-input-select'}, [
      E('option', {value: 'all'}, _('All verdict types')),
      E('option', {value: 'blocked'}, _('Blocked only')),
      E('option', {value: 'observed'}, _('Observed · verdict unknown')),
      E('option', {value: 'allowed'}, _('Allowed · explicit logs only'))
    ]);
    this.proto = E('select', {class: 'cbi-input-select'}, [
      E('option', {value: 'all'}, _('All protocols')),
      E('option', {value: 'tcp'}, 'TCP'),
      E('option', {value: 'udp'}, 'UDP')
    ]);
    this.window = E('select', {class: 'cbi-input-select', title: _('Filter events by log timestamp')}, [
      E('option', {value: 'all'}, _('All loaded')),
      E('option', {value: '5m'}, _('Last 5 minutes')),
      E('option', {value: '15m'}, _('Last 15 minutes')),
      E('option', {value: '1h'}, _('Last hour')),
      E('option', {value: '6h'}, _('Last 6 hours')),
      E('option', {value: '24h'}, _('Last 24 hours'))
    ]);
    this.counter = E('span', {class: 'right'});
    this.statusText = E('span', {class: 'fw-muted'});
    this.pauseButton = E('button', {class: 'cbi-button', click: () => {
      this.paused = !this.paused;
      this.pauseButton.textContent = this.paused ? _('Resume live') : _('Pause live');
      this.statusText.textContent = this.paused ? _('Auto-refresh paused') : _('Auto-refresh every 15s');
    }}, _('Pause live'));
    this.tbody = E('tbody');
    this.insights = E('div', {class: 'fw-insights'});

    const table = E('table', {class: 'table fw-table'}, [
      E('thead', {}, E('tr', {class: 'tr table-titles'},
        ['Time', 'Source / GeoIP', 'Destination', 'Port / Service', 'Proto', 'Event', 'Packet', 'Action']
          .map(t => E('th', {class: 'th'}, _(t))))),
      this.tbody
    ]);

    const result = E('div', {class: 'fw-shell'}, [
      E('p', {class: 'cbi-section-descr fw-description'}, _('Verdicts matter: Blocked requires explicit DROP/REJECT/BLOCK evidence. Observed means INFRA_PORT_HIT saw a packet, but final verdict is unknown because that watch rule returns and normal firewall policy handles it. Allowed appears only when an ALLOW/ACCEPT rule explicitly logs. Select a time window, pause live refresh, inspect top sources/ports/ASNs and scan-like bursts. GeoIP is local; MAC, TOS and packet-ID noise are omitted.')),
      this.stats,
      E('div', {class: 'fw-toolbar'}, [
        this.search, this.kind, this.proto, this.window,
        E('button', {class: 'cbi-button cbi-button-action', click: () => this.refreshEvents().catch(e => ui.addNotification(null, E('p', e.message), 'error'))}, _('Refresh')),
        this.pauseButton,
        E('button', {class: 'cbi-button', click: () => this.exportCSV()}, _('Export CSV')),
        this.counter,
        this.statusText
      ]),
      this.insights,
      E('div', {class: 'fw-tablewrap'}, table)
    ]);

    this.tbody.addEventListener('click', async ev => {
      const button = ev.target.closest('.fw-copy-ip');
      if (!button) return;
      const ip = button.getAttribute('data-ip') || '';
      try {
        if (!navigator.clipboard || !navigator.clipboard.writeText)
          throw new Error('Clipboard API unavailable');
        await navigator.clipboard.writeText(ip);
        ui.addNotification(null, E('p', _('Copied IP: ') + ip), 'info');
      }
      catch (e) {
        ui.addNotification(null, E('p', _('Could not copy automatically. Select the IP text manually.')), 'warning');
      }
    });
    this.search.addEventListener('input', () => this.renderRows());
    this.kind.addEventListener('change', () => { this.kindFilter = this.kind.value; this.renderRows(); });
    this.proto.addEventListener('change', () => { this.protoFilter = this.proto.value; this.renderRows(); });
    this.window.addEventListener('change', () => { this.timeFilter = this.window.value; this.renderRows(); });
    this.statusText.textContent = _('Auto-refresh every 15s');
    this.refreshEvents().catch(e => ui.addNotification(null, E('p', _('Unable to load firewall events: ') + e.message), 'error'));
    this.timer = setInterval(() => {
      if (!this.paused && document.visibilityState === 'visible')
        this.refreshEvents().catch(() => {});
    }, 15000);
    return result;
  },

  exportCSV: function() {
    const rows = [['Time','Source IP','Country','ASN','Destination IP','Destination Port','Service','Protocol','Verdict','Log Marker','Policy Label','Policy Note','Source Port','Interface']];
    this.events.forEach(e => {
      const geo = this.geoCache[e.source] || {};
      rows.push([e.timestamp,e.source,geo.country_name || '',geo.asn_organization || '',e.destination,e.dport,e.service,e.protocol,e.kind,e.marker || e.prefix,e.policyLabel || '',e.policyNote || '',e.sport,e.iface]);
    });
    const csv = rows.map(r => r.map(v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"').join(',')).join('\r\n');
    const url = URL.createObjectURL(new Blob([csv], {type: 'text/csv;charset=utf-8'}));
    const link = E('a', {href: url, download: 'firewall-log.csv'});
    link.click();
    URL.revokeObjectURL(url);
  },

  remove: function() {
    if (this.timer) clearInterval(this.timer);
  }
});
