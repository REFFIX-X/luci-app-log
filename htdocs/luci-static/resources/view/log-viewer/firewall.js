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
  let prefix = '';
  if (line.includes('INFRA_PORT_HIT:')) prefix = 'INFRA_PORT_HIT';
  else if (/\bDROP\b|\bREJECT\b/i.test(line) && /SRC=\S+.*DPT=\d+/.test(line))
    prefix = 'FIREWALL_DROP';
  else return null;

  const fields = parseFields(line);
  const port = Number(fields.DPT || 0);
  const blocked = prefix === 'FIREWALL_DROP' || /\bDROP\b|\bREJECT\b/i.test(line);
  const timestamp = (line.match(/^([A-Z][a-z]{2}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})/) || ['', ''])[1];

  return {
    id: index,
    timestamp: timestamp || 'Recent',
    kind: blocked ? 'Blocked' : 'Probe',
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
  if (!BUNDLED_FLAGS.has(code))
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
    const events = this.events.filter(e => {
      const geo = this.geoCache[e.source] || {};
      const searchable = [
        e.timestamp, e.kind, e.source, e.destination, e.dport, e.service,
        e.protocol, e.prefix, geo.country_name, geo.country_code, geo.asn_organization
      ].join(' ').toLowerCase();
      return (this.kindFilter === 'all' || e.kind.toLowerCase() === this.kindFilter) &&
        (this.protoFilter === 'all' || e.protocol.toLowerCase() === this.protoFilter) &&
        searchable.includes(query);
    }).slice(0, this.maxEntries);

    const blocked = this.events.filter(e => e.kind === 'Blocked').length;
    const probes = this.events.filter(e => e.kind === 'Probe').length;
    const countries = new Set(this.events.map(e => (this.geoCache[e.source] || {}).country_code).filter(Boolean)).size;
    this.stats.innerHTML = [
      ['EVENTS', events.length],
      ['LOGGED BLOCKS', blocked],
      ['PORT PROBES', probes],
      ['COUNTRIES', countries]
    ].map(function(item) {
      return '<div class="fw-stat"><span>' + item[0] + '</span><strong>' + item[1] + '</strong></div>';
    }).join('');

    this.tbody.innerHTML = events.map(e => {
      const geo = this.geoCache[e.source] || {};
      const countryCode = (geo.country_code || '').toUpperCase();
      const country = geo.country_name || 'GeoIP unavailable';
      const asn = geo.asn_organization || '';
      return '<tr class="tr ' + (e.kind === 'Blocked' ? 'fw-blocked' : 'fw-probe') + '">' +
        '<td class="td fw-time">' + esc(e.timestamp) + '</td>' +
        '<td class="td fw-source"><span class="fw-flag" title="' + esc(country) + '">' + countryFlag(countryCode) + '</span> ' +
          '<code>' + esc(e.source) + '</code><small>' + esc(country) + (asn ? ' · ' + esc(asn) : '') + '</small></td>' +
        '<td class="td"><code>' + esc(e.destination || '—') + '</code></td>' +
        '<td class="td"><strong>' + esc(e.dport || '—') + '</strong><small>' + esc(e.service) + '</small></td>' +
        '<td class="td">' + esc(e.protocol) + '</td>' +
        '<td class="td"><span class="fw-badge ' + (e.kind === 'Blocked' ? 'danger' : 'probe') + '">' + esc(e.kind) + '</span></td>' +
        '<td class="td fw-detail">SPT ' + esc(e.sport || '—') + ' · ' + esc(e.flags || '—') +
          '<small>' + esc(e.iface || '—') + (e.ttl ? ' · TTL ' + esc(e.ttl) : '') + '</small></td>' +
        '<td class="td"><a href="https://www.abuseipdb.com/check/' + encodeURIComponent(e.source) +
          '" target="_blank" rel="noreferrer">Reputation ↗</a></td></tr>';
    }).join('') || '<tr><td colspan="8" class="center">No matching firewall events. Check that your firewall rules log the events you want to see.</td></tr>';
    this.counter.textContent = events.length + ' shown · ' + this.events.length + ' loaded';
  },

  render: function() {
    document.head.appendChild(E('style', {type: 'text/css'},
      '.fw-toolbar{display:flex;gap:.6em;flex-wrap:wrap;align-items:center;margin:.8em 0}' +
      '.fw-toolbar input,.fw-toolbar select{min-width:10em}' +
      '.fw-flag{display:inline-flex;min-width:22px;height:16px;margin-right:.25em;align-items:center;justify-content:center;vertical-align:middle}' +
      '.fw-flag-img{display:block;width:20px;max-height:15px;height:auto;object-fit:contain;border:1px solid rgba(127,127,127,.45);border-radius:2px}' +
      '.fw-flag-fallback{font-size:1.1em;line-height:1}' +
      '.fw-stats{display:grid;grid-template-columns:repeat(4,minmax(8em,1fr));gap:.7em;margin:1em 0}' +
      '.fw-stat{border:1px solid var(--border-color,#444);border-radius:8px;padding:1em;background:var(--background-color-secondary,#222)}' +
      '.fw-stat span{display:block;font-size:.75em;opacity:.7;letter-spacing:.06em}.fw-stat strong{font-size:1.5em}' +
      '.fw-tablewrap{overflow:auto;max-height:68vh;border:1px solid var(--border-color,#444);border-radius:8px}' +
      '.fw-table{width:100%;min-width:1000px}.fw-table th{position:sticky;top:0;background:var(--background-color-high,#252a30);z-index:1}' +
      '.fw-source small,.fw-detail small,.fw-table td:nth-child(4) small{display:block;opacity:.72;margin-top:.25em;font-size:.82em}' +
      '.fw-source code{white-space:nowrap}.fw-time{white-space:nowrap;font-size:.9em}' +
      '.fw-badge{border-radius:5px;padding:.15em .55em;font-size:.85em;font-weight:700;white-space:nowrap}' +
      '.fw-badge.danger{background:#a52d32;color:#fff}.fw-badge.probe{background:#8a6a08;color:#fff}' +
      '.fw-blocked{background:rgba(178,45,50,.08)}.fw-probe{background:rgba(194,148,16,.06)}' +
      '@media(max-width:800px){.fw-stats{grid-template-columns:repeat(2,minmax(8em,1fr))}}'
    ));

    this.stats = E('div', {class: 'fw-stats'});
    this.search = E('input', {class: 'cbi-input-text', type: 'search', placeholder: _('Search IP, country, ASN, port or service…')});
    this.kind = E('select', {class: 'cbi-input-select'}, [
      E('option', {value: 'all'}, _('All event types')),
      E('option', {value: 'blocked'}, _('Blocked only')),
      E('option', {value: 'probe'}, _('Probes only'))
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
      E('p', {class: 'cbi-section-descr'}, _('Inbound firewall events. GeoIP is local; MAC, TOS and packet-ID noise are omitted. A probe is not proof of a successful connection.')),
      this.stats,
      E('div', {class: 'fw-toolbar'}, [
        this.search, this.kind, this.proto,
        E('button', {class: 'cbi-button cbi-button-action', click: () => this.refreshEvents().catch(e => ui.addNotification(null, E('p', e.message), 'error'))}, _('Refresh')),
        E('button', {class: 'cbi-button', click: () => this.exportCSV()}, _('Export CSV')),
        this.counter
      ]),
      E('div', {class: 'fw-tablewrap'}, table)
    ]);

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
    const rows = [['Time','Source IP','Country','ASN','Destination IP','Destination Port','Service','Protocol','Event','Source Port','Interface']];
    this.events.forEach(e => {
      const geo = this.geoCache[e.source] || {};
      rows.push([e.timestamp,e.source,geo.country_name || '',geo.asn_organization || '',e.destination,e.dport,e.service,e.protocol,e.kind,e.sport,e.iface]);
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
