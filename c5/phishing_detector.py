"""Challenge 5 - Blockchain Phishing Detector
Run: python phishing_detector.py            (analyses sample URLs, writes warning.html)
     python phishing_detector.py <url> ...
"""
import re, sys
from urllib.parse import urlparse

TRUSTED_DOMAINS = {'metamask.io', 'uniswap.org', 'opensea.io', 'etherscan.io', 'binance.com', 'coinbase.com'}
CRYPTO_KW = ['eth', 'btc', 'crypto', 'token', 'airdrop', 'nft', 'defi', 'swap', 'coin']
WALLET_KW = ['wallet', 'metamask', 'ledger', 'trezor', 'walletconnect', 'wallet-connect', 'seed', 'phrase']
LOGIN_KW  = ['login', 'signin', 'sign-in', 'verify', 'connect', 'auth', 'secure', 'security', 'validate']
URGENT_KW = ['urgent', 'immediately', 'now', 'limited', 'expire', 'suspended', 'act-fast', 'last-chance']
SCAM_KW   = ['free', 'claim', 'giveaway', 'bonus', 'reward', 'win', 'double']
SAFE_TLDS_SUSPECT = ('.xyz', '.top', '.click', '.tk', '.ml', '.ga', '.cf', '.gq', '.work', '.live')

def analyse(url):
    u = urlparse(url if '://' in url else 'http://' + url)
    host, full = (u.hostname or '').lower(), url.lower()
    base = '.'.join(host.split('.')[-2:])
    score, reasons = 0, []
    def hit(pts, why): nonlocal score; score += pts; reasons.append(why)

    if base in TRUSTED_DOMAINS and host in (base, 'www.' + base) and u.scheme == 'https':
        return 0, ['Official trusted domain over HTTPS']
    if u.scheme == 'http':                                hit(15, 'HTTP connection (not encrypted)')
    # brand impersonation: trusted brand name inside a different domain
    for brand in TRUSTED_DOMAINS:
        b = brand.split('.')[0]
        if b in host and base != brand:                   hit(30, f'Impersonates trusted brand "{b}"')
    if base not in TRUSTED_DOMAINS:                       hit(15, 'Suspicious domain (not an official domain)')
    if host.endswith(SAFE_TLDS_SUSPECT):                  hit(10, 'High-abuse TLD')
    if host.count('-') >= 2:                              hit(10, 'Many hyphens in domain')
    if re.fullmatch(r'[\d.]+', host):                     hit(25, 'IP address used instead of domain')
    if '@' in url or 'xn--' in host:                      hit(20, 'Obfuscated URL (@ or punycode)')
    if host.count('.') >= 3:                              hit(10, 'Excessive subdomains')
    for name, kws, pts, label in [
        ('crypto', CRYPTO_KW, 10, 'Crypto keyword'), ('wallet', WALLET_KW, 20, 'Suspicious wallet keyword'),
        ('login',  LOGIN_KW, 20, 'Login-related URL (possible fake login page)'),
        ('urgent', URGENT_KW, 10, 'Urgency language'), ('scam', SCAM_KW, 20, 'Free-token / scam language')]:
        found = [k for k in kws if k in full]
        if found:                                         hit(pts, f'{label}: {", ".join(found[:3])}')
    if len(url) > 75:                                     hit(10, f'Unusually long URL ({len(url)} chars)')
    return min(score, 100), reasons

def level(s):
    return 'CRITICAL' if s >= 75 else 'HIGH' if s >= 55 else 'MEDIUM' if s >= 30 else 'LOW' if s > 0 else 'SAFE'

def warning_html(items):
    cards = ''
    for url, s, lv, rs in items:
        if s < 30: continue
        li = ''.join(f'<li>{r}</li>' for r in rs)
        cards += f'''<div class="card"><div class="top">&#9888; Deceptive site ahead</div>
<p class="url">{url}</p><p>Risk <b>{s}/100 - {lv}</b>. Attackers may steal your seed phrase or drain your wallet.</p>
<ul>{li}</ul><button class="back">Back to safety</button> <a href="#" class="adv">Details</a></div>'''
    return f'''<!doctype html><meta charset="utf-8"><title>Phishing Warning</title><style>
body{{font-family:system-ui;background:#2b0b0b;color:#fff;display:flex;flex-wrap:wrap;gap:20px;justify-content:center;padding:30px}}
.card{{background:#b3261e;border-radius:12px;max-width:420px;padding:20px;box-shadow:0 8px 24px #0008}}
.top{{font-size:22px;font-weight:700;margin-bottom:6px}}.url{{background:#0004;padding:6px;border-radius:6px;word-break:break-all}}
.back{{background:#fff;color:#b3261e;border:0;padding:10px 16px;border-radius:8px;font-weight:700}}.adv{{color:#fff;margin-left:10px}}
</style>{cards}'''

if __name__ == '__main__':
    urls = sys.argv[1:] or ['https://metamask.io', 'http://metamask-wallet-security.com',
                            'https://claim-free-eth.example.com', 'http://wallet-connect-login.example.com']
    items = []
    for u in urls:
        s, rs = analyse(u); lv = level(s); items.append((u, s, lv, rs))
        print('🚨 PHISHING ALERT' if s >= 30 else '✅ SAFE')
        print(f'URL: {u}\nRisk Score: {s}/100   Risk Level: {lv}')
        for r in rs: print(f'  [!] {r}')
        print()
    open('warning.html', 'w').write(warning_html(items)); print('[+] Browser warning mockup saved: warning.html')
