
import re
from collections import Counter

VERIFIED_CONTRACTS = {'0xABC...'}
TRUSTED_OWNERS     = {'UniversityWallet'}
OFFICIAL_SYMBOLS   = {'IqraCoin': 'IQC'}

TOKENS = [
    dict(name='IqraCoin', symbol='IQC', contract='0x123...', owner='Unknown'),
    dict(name='IqraCoin', symbol='IQC', contract='0xABC...', owner='UniversityWallet'),
]

# ---- built-in rules: (points, reason, function(token, all_tokens) -> bool)
RULES = [
    (25, 'Unknown owner',
        lambda t, a: t['owner'].strip().lower() in ('unknown', '', 'none', 'null')),
    (25, 'Duplicate token name',
        lambda t, a: t['contract'] not in VERIFIED_CONTRACTS and Counter(x['name'].lower() for x in a)[t['name'].lower()] > 1),
    (20, 'Unverified contract',
        lambda t, a: t['contract'] not in VERIFIED_CONTRACTS),
    (10, 'Duplicate symbol',
        lambda t, a: t['contract'] not in VERIFIED_CONTRACTS and Counter(x['symbol'].upper() for x in a)[t['symbol'].upper()] > 1),
    (15, 'Unusual ownership (owner is not a trusted entity)',
        lambda t, a: t['owner'] not in TRUSTED_OWNERS),
    (10, 'Symbol does not match official symbol',
        lambda t, a: t['name'] in OFFICIAL_SYMBOLS and OFFICIAL_SYMBOLS[t['name']] != t['symbol']),
    (10, 'Suspicious metadata (scam keywords / odd characters)',
        lambda t, a: bool(re.search(r'(?i)free|airdrop|bonus|claim|2x|elon|[^\w\s.]', t['name'] + t['symbol']))),
    (10, 'Malformed contract address',
        lambda t, a: not re.fullmatch(r'0x[0-9a-fA-F.]{3,}', t['contract'])),
]
CUSTOM_RULES = []      # students add their own with add_rule()

def add_rule(points, reason, fn):
    """BONUS: custom security rule. fn(token, all_tokens) -> True if risky."""
    CUSTOM_RULES.append((points, reason, fn))

def check(token, tokens):
    score, reasons = 0, []
    for pts, why, fn in RULES + CUSTOM_RULES:
        if fn(token, tokens):
            score += pts; reasons.append(why)
    return min(score, 100), reasons

def level(s):
    return 'CRITICAL' if s >= 85 else 'HIGH' if s >= 60 else 'MEDIUM' if s >= 30 else 'LOW'

def report(tokens):
    for t in tokens:
        s, reasons = check(t, tokens)
        print('TOKEN SECURITY REPORT')
        print(f"Token: {t['name']} ({t['symbol']})  Contract: {t['contract']}  Owner: {t['owner']}")
        print(f'Risk Score: {s}/100   Risk: {level(s)}')
        for r in reasons: print(f'  [!] {r}')
        print('  VERDICT:', 'DO NOT INTERACT - likely FAKE' if s >= 60 else 'Looks LEGITIMATE' if s < 30 else 'Be careful')
        print()

if __name__ == '__main__':
    # custom rule demo (bonus): flag any contract that is not 0x-prefixed uppercase hex
    add_rule(5, 'Custom: contract id not in whitelist', lambda t, a: t['contract'] == '0x123...')
    report(TOKENS)
