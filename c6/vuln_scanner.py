
import re, sys

RULES = [
 ('HIGH',   'tx.origin used for auth',        r'tx\.origin',                          'Use msg.sender'),
 ('HIGH',   'selfdestruct present',           r'selfdestruct\s*\(',                   'Remove or restrict with onlyOwner'),
 ('HIGH',   'delegatecall present',           r'\.delegatecall\s*\(',                 'Avoid / whitelist target'),
 ('MEDIUM', 'Unchecked send()',               r'^\s*[\w.]+\.send\s*\(',               'require(success) or use call'),
 ('MEDIUM', 'unchecked { } block',            r'unchecked\s*\{',                      'Remove unless proven safe'),
 ('LOW',    'Weak randomness (block vars)',   r'block\.(timestamp|number|difficulty)', 'Use Chainlink VRF'),
 ('LOW',    'transfer() 2300 gas limit',      r'\.transfer\s*\(',                     'Use call + CEI/nonReentrant'),
]

def func_blocks(src):
    """yield (name, header, body) for each function using brace matching"""
    for m in re.finditer(r'function\s+(\w+)\s*\(([^)]*)\)([^{;]*)\{', src):
        i, depth = m.end(), 1
        while depth and i < len(src):
            depth += {'{': 1, '}': -1}.get(src[i], 0); i += 1
        yield m.group(1), m.group(0), src[m.end():i], src[:m.start()].count('\n') + 1

def scan(src):
    src = re.sub(r'//[^\n]*', '', src)          # ignore comments (keeps line numbers)
    out = []
    for ln, line in enumerate(src.splitlines(), 1):
        for sev, name, rx, fix in RULES:
            if re.search(rx, line):
                out.append((sev, name, ln, fix))
    for name, header, body, ln in func_blocks(src):
        hdr = header.lower()
        public = ' public' in hdr or ' external' in hdr
        guarded = re.search(r'onlyowner|require\s*\(\s*msg\.sender\s*==', hdr + body.lower())
        # reentrancy: external call before a state write
        call = re.search(r'\.call\{|\.call\(', body)
        if call and re.search(r'(\]|\w)\s*(-=|\+=|=)[^=]', body[call.end():]):
            if 'nonreentrant' not in hdr:
                out.append(('HIGH', f'Reentrancy risk in {name}()', ln, 'CEI pattern + nonReentrant'))
        if public and not guarded and re.search(r'\bowner\s*=|selfdestruct|\.transfer\(address\(this\)\.balance', body):
            out.append(('CRITICAL', f'Missing access control in {name}()', ln, 'Add onlyOwner'))
        if re.search(r'for\s*\([^)]*\.length', body) and public:
            out.append(('MEDIUM', f'Unbounded loop in {name}()', ln, 'Paginate'))
    return sorted(set(out), key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x[0]))

if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'VulnerableVault.sol'
    res = scan(open(path).read())
    print(f'SMART CONTRACT SCAN: {path}\n' + '=' * 60)
    for sev, name, ln, fix in res:
        print(f'[{sev:<8}] line {ln:<3} {name}\n           fix: {fix}')
    print('=' * 60 + f'\n{len(res)} issue(s) found')
