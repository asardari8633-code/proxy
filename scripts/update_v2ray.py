#!/usr/bin/env python3
"""منابع عمومی کانفیگ را می‌گیرد، پاک‌سازی و فیلتر می‌کند، پورت را تست می‌کند
و sub.txt (لینک اشتراک) و configs.json (لیست سایت) را می‌سازد."""
import asyncio, base64, hashlib, ipaddress, json, os, re, sys, time, urllib.parse, urllib.request

SITE = 'https://asardari8633-code.github.io/proxy/'
REPO = 'https://github.com/asardari8633-code/proxy'
BRAND = 'Nexora Core'
MAX_ITEMS, PER_PROTO, TCP_TIMEOUT = 120, 60, 4.0
SOURCES = [
    ('SS44-sub', 'https://github.com/ZendanTeam/SS44-sub', [
        'https://raw.githubusercontent.com/ZendanTeam/SS44-sub/main/SS44-gold.txt',
        'https://cdn.jsdelivr.net/gh/ZendanTeam/SS44-sub@main/SS44-gold.txt']),
    ('PulseConfigs', 'https://github.com/drmikecrypto/PulseConfigs', [
        'https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/verified/configs_base64.txt',
        'https://cdn.jsdelivr.net/gh/drmikecrypto/PulseConfigs@main/verified/configs_base64.txt']),
]
GOOD_SS = {'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305'}
WEAK_PW = {'shadowsocks', 'password', '123456', 'test'}
PN = {'vless': 'VLESS', 'vmess': 'VMess', 'trojan': 'Trojan', 'ss': 'SS'}
SN = {'reality': 'Reality', 'tls': 'TLS'}


def b64d(s):
    s = urllib.parse.unquote(s).strip().replace('-', '+').replace('_', '/')
    s = re.sub(r'[^A-Za-z0-9+/]', '', s)
    return base64.b64decode(s + '=' * (-len(s) % 4))


def fetch(urls):
    for u in urls:
        try:
            with urllib.request.urlopen(urllib.request.Request(u, headers={'User-Agent': 'nexora-updater'}), timeout=30) as r:
                t = r.read().decode('utf-8', 'replace')
            if t.strip():
                return t
        except Exception as e:
            print('fetch failed:', u, e)
    return None


def expand(text):
    if re.search(r'(vmess|vless|trojan|ss)://', text[:3000]):
        return text
    try:
        return b64d(text).decode('utf-8', 'replace')
    except Exception:
        return ''


def truthy(v):
    return str(v).lower() in ('1', 'true')


def p_vmess(rest, line):
    j = json.loads(b64d(rest.split('#', 1)[0]).decode('utf-8', 'replace'))
    host, port, cid = str(j.get('add') or '').strip(), int(j.get('port')), str(j.get('id') or '').strip().lower()
    if not host or not cid or not 0 < port < 65536:
        return None
    tls = str(j.get('tls') or '').lower() == 'tls'
    return dict(proto='vmess', host=host, port=port, cred=cid, net=str(j.get('net') or 'tcp'),
                sec='tls' if tls else 'none', insecure=bool(tls and j.get('skip-cert-verify')), raw=j, line=line)


def p_url(proto, rest, line):
    u = urllib.parse.urlsplit(proto + '://' + rest)
    host, port, cred = u.hostname, u.port, urllib.parse.unquote(u.username or '')
    if not host or not port or not cred:
        return None
    q = {k.lower(): v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    sec = (q.get('security') or ('tls' if proto == 'trojan' else 'none')).lower()
    return dict(proto=proto, host=host, port=port, cred=cred, net=(q.get('type') or 'tcp').lower(), sec=sec,
                insecure=truthy(q.get('allowinsecure', '0')) or truthy(q.get('insecure', '0')), line=line)


def p_ss(rest, line):
    body = rest.split('#', 1)[0].split('?', 1)[0]
    if '@' in body:
        ui, hp = body.rsplit('@', 1)
        ui = urllib.parse.unquote(ui)
        if ':' not in ui:
            ui = b64d(ui).decode()
    else:
        ui, hp = b64d(body).decode().rsplit('@', 1)
    method, pw = ui.split(':', 1)
    host, port = hp.rsplit(':', 1)
    host, port = host.strip('[]'), int(port.strip('/'))
    if not host or not pw or not 0 < port < 65536:
        return None
    return dict(proto='ss', host=host, port=port, cred=pw, method=method.lower(), net='tcp', sec='none', insecure=False, line=line)


def parse(line):
    line = line.strip()
    m = re.match(r'^(vmess|vless|trojan|ss)://(.+)$', line, re.I)
    if not m or re.search(r'\s', line.split('#', 1)[0]):  # فاصله داخل لینک = خط خراب
        return None
    proto, rest = m.group(1).lower(), m.group(2)
    try:
        return p_vmess(rest, line) if proto == 'vmess' else p_ss(rest, line) if proto == 'ss' else p_url(proto, rest, line)
    except Exception:
        return None


def reject(c):
    p = c['proto']
    try:
        ip = ipaddress.ip_address(c['host'])
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return 'private'
    except ValueError:
        pass
    if c['insecure']:
        return 'تأیید گواهی خاموش'
    if p == 'vless' and c['sec'] not in ('tls', 'reality'):
        return 'بدون رمزنگاری'
    if p == 'trojan' and c['sec'] != 'tls':
        return 'بدون TLS'
    if p == 'ss' and (not (c['method'] in GOOD_SS or c['method'].startswith('2022-')) or c['cred'].lower() in WEAK_PW):
        return 'رمزنگاری یا رمز ضعیف'
    return None


def make_link(c, name):
    if c['proto'] == 'vmess':
        j = {k: ('' if v is None else v) for k, v in c['raw'].items() if k not in ('skip-cert-verify', 'name')}
        j.update(v='2', ps=name, port=str(c['port']), aid=str(j.get('aid') or '0'))
        return 'vmess://' + base64.b64encode(json.dumps(j, ensure_ascii=False, separators=(',', ':')).encode()).decode()
    return c['line'].split('#', 1)[0] + '#' + urllib.parse.quote(name, safe='')


async def probe(c, sem):
    async with sem:
        t = time.perf_counter()
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(c['host'], c['port']), TCP_TIMEOUT)
            w.close()
            return int((time.perf_counter() - t) * 1000)
        except Exception:
            return None


async def probe_all(cs):
    sem = asyncio.Semaphore(80)
    return await asyncio.gather(*(probe(c, sem) for c in cs))


def main():
    args = sys.argv[1:]
    no_tcp = '--no-tcp' in args
    out = args[args.index('--out') + 1] if '--out' in args else '.'
    local = args[args.index('--local') + 1:] if '--local' in args else []
    local = [a for a in local if not a.startswith('--')]
    seen, cands, stats, dropped = {}, [], [], {}
    for i, (sname, surl, urls) in enumerate(SOURCES):
        text = open(local[i], encoding='utf-8').read() if i < len(local) else fetch(urls)
        n = 0
        for line in expand(text or '').splitlines():
            c = parse(line)
            if not c:
                continue
            n += 1
            why = reject(c)
            if why:
                dropped[why] = dropped.get(why, 0) + 1
                continue
            key = f"{c['proto']}|{c['host'].lower()}|{c['port']}|{c['cred']}"
            if key in seen:
                continue
            c['src'], c['id'] = sname, hashlib.sha1(key.encode()).hexdigest()[:6]
            seen[key] = c
            cands.append(c)
        stats.append({'name': sname, 'url': surl, 'valid': n})
    print('sources:', stats, '| dropped:', dropped, '| candidates:', len(cands))
    if not cands:
        print('nothing parsed; leaving files untouched'); return
    ms = [100] * len(cands) if no_tcp else asyncio.run(probe_all(cands))
    alive = [(c, m) for c, m in zip(cands, ms) if m is not None]
    print('port open:', len(alive), 'of', len(cands))
    if len(alive) < (1 if no_tcp else 8):
        print('too few reachable (runner problem?); leaving files untouched'); return
    path = os.path.join(out, 'configs.json')
    old = {}
    if os.path.exists(path):
        try: old = json.load(open(path, encoding='utf-8'))
        except Exception: old = {}
    oldms = {i.get('id'): i.get('ms') for i in old.get('items', [])}
    for c, m in alive:  # پینگ گرد می‌شود و تا وقتی تغییر بزرگ نشده همان قبلی می‌ماند (کامیت اضافه نخورد)
        m, o = max(10, int(round(m / 10.0)) * 10), oldms.get(c['id'])
        c['ms'] = o if o and abs(m - o) <= max(60, o * 0.5) else m
    rank = {'reality': 0, 'tls': 1}
    alive.sort(key=lambda x: (rank.get(x[0]['sec'], 2), x[0]['ms'] // 50, x[0]['id']))
    items, per = [], {}
    for c, _ in alive:
        if per.get(c['proto'], 0) >= PER_PROTO or len(items) >= MAX_ITEMS:
            continue
        per[c['proto']] = per.get(c['proto'], 0) + 1
        name = f"{BRAND} | {PN[c['proto']]} {SN.get(c['sec'], '')}".rstrip() + f" | {c['id'][:4]}"
        items.append({'id': c['id'], 'p': c['proto'], 'h': c['host'], 'pt': c['port'], 'n': c['net'],
                      's': c['sec'], 'ms': c['ms'], 'src': c['src'], 'name': name, 'l': make_link(c, name)})
    body = {'count': len(items), 'sources': stats, 'items': items}
    if {k: old.get(k) for k in body} == body:
        print('no change'); return
    title = base64.b64encode(f'{BRAND} | کانفیگ رایگان'.encode()).decode()
    sub = '\n'.join([f'#profile-title: base64:{title}', '#profile-update-interval: 1', f'#support-url: {REPO}',
                     f'#profile-web-page-url: {SITE}v2ray.html'] + [i['l'] for i in items]) + '\n'
    open(os.path.join(out, 'sub.txt'), 'w', encoding='utf-8').write(sub)
    open(path, 'w', encoding='utf-8').write(json.dumps({'updated': int(time.time()), **body}, ensure_ascii=False, separators=(',', ':')))
    print('written:', len(items), 'configs', per)


main()
