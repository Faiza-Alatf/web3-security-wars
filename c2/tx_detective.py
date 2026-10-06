"""Challenge 2 - Blockchain Transaction Detective
Usage: python tx_detective.py transactions.txt
Creates tx_graph.png (bonus) if matplotlib is installed.
"""
import re, sys
from collections import defaultdict

SUSPICIOUS_WALLETS = {'scamwallet', 'mixer', 'unknown', 'tornado', 'darkmarket'}
MIXERS             = {'mixer', 'tornado'}
LARGE_TX_ETH       = 5       # single transfer >= 5 ETH is "large"

def parse(path):
    txs = []
    text = re.sub(r'\s*\n\s*\|', ' |', open(path).read())   # fix broken lines
    for m in re.finditer(r'(TX\d+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([\d.]+)\s*ETH', text):
        txs.append(dict(id=m[1], src=m[2].strip(), dst=m[3].strip(), amt=float(m[4])))
    return txs

def analyse(txs):
    risk = defaultdict(lambda: dict(score=0, reasons=[]))
    def add(w, pts, why):
        if why not in risk[w]['reasons']:
            risk[w]['reasons'].append(why)
        risk[w]['score'] += pts
    incoming = defaultdict(float); outgoing = defaultdict(float)
    for t in txs:
        incoming[t['dst']] += t['amt']; outgoing[t['src']] += t['amt']
    for t in txs:
        s, d, a = t['src'], t['dst'], t['amt']
        if a >= LARGE_TX_ETH:
            add(d, 25, f"Large transaction ({a:g} ETH in {t['id']})")
        if d.lower() in SUSPICIOUS_WALLETS:
            add(d, 30, 'Known suspicious wallet')
            if s.lower() not in SUSPICIOUS_WALLETS:
                add(s, 15, f'Sent funds to suspicious wallet {d}')
        if d.lower() in MIXERS:
            add(d, 30, 'Funds transferred to mixer')
            add(s, 20, 'Funds sent to a mixer (laundering pattern)')
        if s.lower() in SUSPICIOUS_WALLETS and d.lower() not in SUSPICIOUS_WALLETS:
            add(d, 15, f'Received funds from suspicious wallet {s}')
        if s.lower() in SUSPICIOUS_WALLETS and d.lower() in SUSPICIOUS_WALLETS:
            add(d, 15, 'Connected to suspicious wallet')
            add(s, 15, 'Connected to suspicious wallet')
    # pass-through: receives then forwards most of the funds quickly
    for w in set(incoming) & set(outgoing):
        if incoming[w] and outgoing[w] / incoming[w] >= 0.8 and incoming[w] >= LARGE_TX_ETH:
            add(w, 20, f'Pass-through behaviour ({outgoing[w]:g}/{incoming[w]:g} ETH forwarded)')
    for w in risk:
        risk[w]['score'] = min(100, risk[w]['score'])
    return risk

def severity(s):
    return 'CRITICAL' if s >= 80 else 'HIGH' if s >= 60 else 'MEDIUM' if s >= 35 else 'LOW'

def draw_graph(txs, risk, out='tx_graph.png'):
    try:
        import matplotlib; matplotlib.use('Agg')
        import matplotlib.pyplot as plt, math
    except ImportError:
        print('[i] matplotlib not installed - skipping graph'); return
    nodes = sorted({t['src'] for t in txs} | {t['dst'] for t in txs})
    pos = {n: (math.cos(2*math.pi*i/len(nodes)), math.sin(2*math.pi*i/len(nodes))) for i, n in enumerate(nodes)}
    fig, ax = plt.subplots(figsize=(8, 6)); ax.axis('off')
    for t in txs:
        (x1, y1), (x2, y2) = pos[t['src']], pos[t['dst']]
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle='->', lw=1 + t['amt']/4, color='#555', shrinkA=18, shrinkB=18))
        ax.text((x1+x2)/2, (y1+y2)/2, f"{t['id']}\n{t['amt']:g} ETH", fontsize=8, ha='center',
                bbox=dict(fc='white', ec='none', alpha=.8))
    for n, (x, y) in pos.items():
        sc = risk[n]['score'] if n in risk else 0
        col = '#d62728' if sc >= 80 else '#ff7f0e' if sc >= 50 else '#ffbf00' if sc >= 25 else '#2ca02c'
        ax.scatter(x, y, s=1800, c=col, zorder=3); ax.text(x, y, n, ha='center', va='center', fontsize=8, weight='bold', zorder=4)
    ax.set_title('Transaction Graph (red = critical, green = safe)')
    fig.savefig(out, dpi=150, bbox_inches='tight'); print(f'[+] Graph saved: {out}')

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'transactions.txt'
    txs = parse(path)
    print(f'Parsed {len(txs)} transactions\n')
    risk = analyse(txs)
    for w, r in sorted(risk.items(), key=lambda kv: -kv[1]['score']):
        if r['score'] < 25:
            continue
        print('🚨 SUSPICIOUS TRANSACTION')
        print(f"Wallet: {w}   Risk Score: {r['score']}/100   Severity: {severity(r['score'])}")
        print('Reasons:')
        for why in r['reasons']:
            print(f'  - {why}')
        print()
    draw_graph(txs, risk)

if __name__ == '__main__':
    main()
