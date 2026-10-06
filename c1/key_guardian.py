"""Challenge 1 - Private Key Guardian
Usage: python key_guardian.py sample_secrets.txt [--mask-output masked.txt]
"""
import re, sys

PRIVATE_KEY = re.compile(r'\b(?:0x)?[a-fA-F0-9]{64}\b')            # 256-bit key
WALLET_ADDR = re.compile(r'\b0x[a-fA-F0-9]{40}\b')                  # ETH address
SECRET_KV   = re.compile(r'(?i)\b([\w]*(?:api[_-]?key|secret|password|passwd|token|private[_-]?key|mnemonic)[\w]*)\s*[=:]\s*["\']?([^\s"\']+)')
SEED_PHRASE = re.compile(r'\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b')  # 12-24 words

def mask(s: str) -> str:
    """0xA123456789ABCDE -> 0xA123****CDE"""
    if len(s) <= 8:
        return s[:2] + '****'
    head = 6 if s.startswith('0x') else 4
    return s[:head] + '****' + s[-3:]

def scan(text: str):
    findings = []
    for ln, line in enumerate(text.splitlines(), 1):
        for m in PRIVATE_KEY.finditer(line):
            findings.append(dict(line=ln, type='PRIVATE_KEY', value=m.group(), weight=60))
        for m in WALLET_ADDR.finditer(line):
            findings.append(dict(line=ln, type='WALLET_ADDRESS', value=m.group(), weight=5))
        for m in SECRET_KV.finditer(line):
            val = m.group(2)
            if PRIVATE_KEY.fullmatch(val):      # already reported as private key
                continue
            findings.append(dict(line=ln, type='SECRET/' + m.group(1).upper(), value=val, weight=20))
        if SEED_PHRASE.search(line):
            findings.append(dict(line=ln, type='SEED_PHRASE', value=SEED_PHRASE.search(line).group(), weight=70))
    return findings

def risk_score(findings):
    return min(100, sum(f['weight'] for f in findings))

def level(score):
    return ('CRITICAL' if score >= 80 else 'HIGH' if score >= 60 else
            'MEDIUM' if score >= 30 else 'LOW')

def mask_text(text, findings):
    for f in sorted(findings, key=lambda x: -len(x['value'])):
        text = text.replace(f['value'], mask(f['value']))
    return text

def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    text = open(sys.argv[1], encoding='utf-8', errors='ignore').read()
    findings = scan(text)
    score = risk_score(findings)
    print('=' * 60)
    print('  PRIVATE KEY GUARDIAN - SCAN REPORT')
    print('=' * 60)
    for f in findings:
        print(f"  Line {f['line']:<3} {f['type']:<28} {mask(f['value'])}")
    print('-' * 60)
    print(f"  Total findings : {len(findings)}")
    print(f"  Risk Score     : {score}/100   Severity: {level(score)}")
    if score >= 30:
        print('\n  [!] SECURITY WARNING: Secrets exposed in plain text!')
        print('  [!] Rotate/revoke keys immediately, move secrets to a .env /')
        print('      vault / hardware wallet, add file to .gitignore, and')
        print('      never commit it to GitHub.')
    if '--mask-output' in sys.argv:
        out = sys.argv[sys.argv.index('--mask-output') + 1]
        open(out, 'w').write(mask_text(text, findings))
        print(f"\n  [+] Masked copy saved to {out}")

if __name__ == '__main__':
    main()
