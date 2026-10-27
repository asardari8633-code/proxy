#!/usr/bin/env python3
"""seen.json را از روی لیست منبع به‌روز می‌کند: هر پروکسی چه زمانی برای اولین بار در لیست دیده شده."""
import base64, json, os, re, sys, time, urllib.parse, urllib.request

SRC = [
    'https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt',
    'https://cdn.jsdelivr.net/gh/SoliSpirit/mtproto@master/all_proxies.txt',
]
OUT = 'seen.json'
KEEP_DAYS = 7  # پروکسیِ غایب از لیست، تا این‌قدر نگه داشته می‌شود (اگر برگشت «جدید» حساب نشود)


def norm(s):  # باید دقیقاً مثل norm() در صفحه باشد
    s = str(s)
    if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0:
        return s.lower()
    try:
        t = re.sub(r'[^A-Za-z0-9+/]', '', s.replace('-', '+').replace('_', '/'))
        t += '=' * (-len(t) % 4)
        return base64.b64decode(t).hex()
    except Exception:
        return s


def nkey(s, p, k):
    return re.sub(r'\.$', '', str(s).lower()) + ':' + str(p) + ':' + norm(k)


def b36(n):
    d = '0123456789abcdefghijklmnopqrstuvwxyz'
    out = ''
    while True:
        n, r = divmod(n, 36)
        out = d[r] + out
        if n == 0:
            return out


def H(s):  # باید دقیقاً مثل H() در صفحه باشد (FNV-1a دوگانه روی واحدهای UTF-16)
    a, b = 0x811C9DC5, 0x9747B28C
    data = s.encode('utf-16-le')
    for i in range(0, len(data), 2):
        c = data[i] | (data[i + 1] << 8)
        a = ((a ^ c) * 16777619) & 0xFFFFFFFF
        b = ((b ^ c) * 0x5BD1E995) & 0xFFFFFFFF
    return b36(a) + b36(b)


def fetch():
    if len(sys.argv) > 1:  # برای تست محلی
        return open(sys.argv[1], encoding='utf-8').read()
    for u in SRC:
        try:
            req = urllib.request.Request(u, headers={'User-Agent': 'seen-updater'})
            with urllib.request.urlopen(req, timeout=30) as r:
                t = r.read().decode('utf-8', 'replace')
            if t.strip():
                return t
        except Exception as e:
            print('fetch failed:', u, e)
    return None


def parse(text):
    keys = set()
    for l in text.splitlines():
        l = l.strip()
        if not l:
            continue
        try:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(re.sub(r'^tg://', 'https://t.me/', l)).query)
            s, p, k = (q.get(x, [None])[0] for x in ('server', 'port', 'secret'))
        except Exception:
            continue
        if s and p and k:
            keys.add(H(nkey(s, p, k)))
    return keys


def main():
    text = fetch()
    if text is None:
        print('no source available; leaving seen.json untouched')
        return
    keys = parse(text)
    if not keys:
        print('empty list; leaving seen.json untouched')
        return
    now = int(time.time())
    today = now // 86400
    old = {}
    if os.path.exists(OUT):
        try:
            old = json.load(open(OUT, encoding='utf-8'))
        except Exception:
            old = {}
    seed = old.get('seed') or now
    prev = old.get('p', {})
    new = {}
    for h in keys:
        new[h] = [prev[h][0] if h in prev else now, today]
    for h, v in prev.items():
        if h not in keys and today - v[1] <= KEEP_DAYS:
            new[h] = v
    out = json.dumps({'seed': seed, 'p': new}, separators=(',', ':'), sort_keys=True)
    if not os.path.exists(OUT) or open(OUT, encoding='utf-8').read() != out:
        open(OUT, 'w', encoding='utf-8').write(out)
    print(f'{len(keys)} in list, {len(new)} tracked')


main()
