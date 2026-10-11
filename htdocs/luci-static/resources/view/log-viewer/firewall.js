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

  // Recognise both kernel verdict text and explicit log prefixes such as
  // JELLYFIN_BLOCK:, FIREWALL_BLOCK:, ALLOW: or ACCEPTED:. No service-specific
  // rules are hardcoded; this only interprets markers already in the log.
  const blockMarker = /\b(?:DROP|REJECT)\b/i.test(line) ||
    /(?:^|[\s:])[A-Z0-9_-]*(?:BLOCKED|BLOCK|DROP|REJECT):/i.test(line);
  const allowMarker =
    /(?:^|[\s:])[A-Z0-9_-]*(?:ALLOWED|ALLOW|ACCEPTED|ACCEPT|PASSED|PASS):/i.test(line);

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

  return {
    id: index,
    timestamp: timestamp || 'Recent',
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
    prefix: prefix
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
    const raw = await this.getLogData();
    const lines = (raw || '').trim().split('\n');
    this.events = lines.map((line, i) => parseLine(line, i + 1))
      .filter(Boolean).slice(-MAX_LINES).reverse();
    await this.enrich(this.events.slice(0, 60));
    this.renderRows();
  },

  renderRows: function() {
    if (!this.tbody) return;
    const query = (this.search.value || '').toLowerCase();
    const matching = this.events.filter(e => {
      const geo = this.geoCache[e.source] || {};
      const searchable = [
        e.timestamp, e.kind, e.source, e.destination, e.dport, e.service,
        e.protocol, e.prefix, geo.country_name, geo.country_code, geo.asn_organization
      ].join(' ').toLowerCase();
      return (this.kindFilter === 'all' || e.kind.toLowerCase() === this.kindFilter) &&
        (this.protoFilter === 'all' || e.protocol.toLowerCase() === this.protoFilter) &&
        searchable.includes(query);
    });
    const events = matching.slice(0, this.maxEntries);
    const blocked = matching.filter(e => e.kind === 'Blocked').length;
    const observed = matching.filter(e => e.kind === 'Observed').length;
    const allowed = matching.filter(e => e.kind === 'Allowed').length;
    const countries = new Set(matching.map(e => (this.geoCache[e.source] || {}).country_code).filter(Boolean)).size;
    this.stats.innerHTML = [
      ['MATCHING EVENTS', matching.length],
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
      return '<tr class="tr fw-' + kindClass + '">' +
        '<td class="td fw-time">' + esc(e.timestamp) + '</td>' +
        '<td class="td fw-source"><span class="fw-flag" title="' + esc(country) + '">' + countryFlag(countryCode) + '</span> ' +
          '<code>' + esc(e.source) + '</code> <button type="button" class="cbi-button fw-copy-ip" data-ip="' + esc(e.source) + '" title="Copy source IP">Copy</button>' +
          '<small>' + esc(country) + (asn ? ' · ' + esc(asn) : '') + '</small></td>' +
        '<td class="td"><code>' + esc(e.destination || '—') + '</code></td>' +
        '<td class="td"><strong>' + esc(e.dport || '—') + '</strong><small>' + esc(e.service) + '</small></td>' +
        '<td class="td">' + esc(e.protocol) + '</td>' +
        '<td class="td"><span class="fw-badge ' + kindClass + '" title="' + esc(e.prefix) + '">' + esc(e.kind) + '</span></td>' +
        '<td class="td fw-detail">SPT ' + esc(e.sport || '—') + ' · ' + esc(e.flags || '—') +
          '<small>' + esc(e.iface || '—') + (e.ttl ? ' · TTL ' + esc(e.ttl) : '') + '</small></td>' +
        '<td class="td"><a href="https://www.abuseipdb.com/check/' + encodeURIComponent(e.source) +
          '" target="_blank" rel="noreferrer">Reputation ↗</a></td></tr>';
    }).join('') || '<tr><td colspan="8" class="center">No matching events in the recent log buffer. Only explicitly logged DROP/REJECT/BLOCK and ALLOW/ACCEPT markers can prove a firewall verdict.</td></tr>';
    this.counter.textContent = events.length + ' shown · ' + matching.length + ' matched · ' + this.events.length + ' loaded';
  },

  render: function() {
    document.head.appendChild(E('style', {type: 'text/css'},
      '.fw-toolbar{display:flex;gap:.6em;flex-wrap:wrap;align-items:center;margin:.8em 0}' +
      '.fw-toolbar input,.fw-toolbar select{min-width:10em}' +
      '.fw-flag{display:inline-flex;min-width:22px;height:16px;margin-right:.25em;align-items:center;justify-content:center;vertical-align:middle}' +
      '.fw-flag-img{display:block;width:20px;max-height:15px;height:auto;object-fit:contain;border:1px solid rgba(127,127,127,.45);border-radius:2px}' +
      '.fw-flag-fallback{font-size:1.1em;line-height:1}' +
      '.fw-stats{display:grid;grid-template-columns:repeat(5,minmax(7em,1fr));gap:.7em;margin:1em 0}' +
      '.fw-stat{border:1px solid var(--border-color,#444);border-radius:8px;padding:1em;background:var(--background-color-secondary,#222)}' +
      '.fw-stat span{display:block;font-size:.75em;opacity:.7;letter-spacing:.06em}.fw-stat strong{font-size:1.5em}' +
      '.fw-tablewrap{overflow:auto;max-height:68vh;border:1px solid var(--border-color,#444);border-radius:8px}' +
      '.fw-table{width:100%;min-width:1000px}.fw-table th{position:sticky;top:0;background:var(--background-color-high,#252a30);z-index:1}' +
      '.fw-source small,.fw-detail small,.fw-table td:nth-child(4) small{display:block;opacity:.72;margin-top:.25em;font-size:.82em}' +
      '.fw-source code{white-space:nowrap}.fw-time{white-space:nowrap;font-size:.9em}' +
      '.fw-badge{border-radius:5px;padding:.15em .55em;font-size:.85em;font-weight:700;white-space:nowrap}' +
      '.fw-badge.danger{background:#a52d32;color:#fff}.fw-badge.observed{background:#8a6a08;color:#fff}.fw-badge.allowed{background:#246d49;color:#fff}' +
      '.fw-blocked{background:rgba(178,45,50,.08)}.fw-observed{background:rgba(194,148,16,.06)}.fw-allowed{background:rgba(36,109,73,.08)}' +
      '.fw-copy-ip{font-size:.75em;min-height:1.6em;padding:.05em .4em;margin-left:.25em}' +
      '@media(max-width:800px){.fw-stats{grid-template-columns:repeat(2,minmax(8em,1fr))}}'
    ));

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
    this.counter = E('span', {class: 'right'});
    this.tbody = E('tbody');

    const table = E('table', {class: 'table fw-table'}, [
      E('thead', {}, E('tr', {class: 'tr table-titles'},
        ['Time', 'Source / GeoIP', 'Destination', 'Port / Service', 'Proto', 'Event', 'Packet', 'Action']
          .map(t => E('th', {class: 'th'}, _(t))))),
      this.tbody
    ]);

    const result = E('div', {}, [
      E('p', {class: 'cbi-section-descr'}, _('Verdicts matter: Blocked requires an explicit DROP/REJECT/BLOCK log. Observed means INFRA_PORT_HIT saw a packet; that logging-only rule does not decide the verdict, and the normal firewall may still drop it later. Allowed appears only when an ALLOW/ACCEPT rule explicitly logs the packet. Silent allowed traffic cannot be inferred here. GeoIP is local; MAC, TOS and packet-ID noise are omitted.')),
      this.stats,
      E('div', {class: 'fw-toolbar'}, [
        this.search, this.kind, this.proto,
        E('button', {class: 'cbi-button cbi-button-action', click: () => this.refreshEvents().catch(e => ui.addNotification(null, E('p', e.message), 'error'))}, _('Refresh')),
        E('button', {class: 'cbi-button', click: () => this.exportCSV()}, _('Export CSV')),
        this.counter
      ]),
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
    this.refreshEvents().catch(e => ui.addNotification(null, E('p', _('Unable to load firewall events: ') + e.message), 'error'));
    this.timer = setInterval(() => {
      if (document.visibilityState === 'visible') this.refreshEvents().catch(() => {});
    }, 15000);
    return result;
  },

  exportCSV: function() {
    const rows = [['Time','Source IP','Country','ASN','Destination IP','Destination Port','Service','Protocol','Verdict','Log Marker','Source Port','Interface']];
    this.events.forEach(e => {
      const geo = this.geoCache[e.source] || {};
      rows.push([e.timestamp,e.source,geo.country_name || '',geo.asn_organization || '',e.destination,e.dport,e.service,e.protocol,e.kind,e.prefix,e.sport,e.iface]);
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
