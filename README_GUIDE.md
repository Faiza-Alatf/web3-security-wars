# Web3 Security Wars – Assignment Guide (Roman Urdu)

## Assignment kya hai?
Blockchain Assignment No 2 ("Blockchain Security Hackathon"). Team ko **45 minutes** mein ek security problem
investigate / exploit / detect / secure karni hoti hai. Marks theory ke nahi, in cheezon ke hain:
working code, security thinking, problem-solving, AI ka smart (aur critical) use, creativity, aur explain/defend karna.
Formula: **Working Code + Correct Security Finding + Successful Test + Clear Explanation.**

7 challenges hain (team ko usually 1 allocate hota hai, lekin yahan SAB ready hain):

| # | Challenge | Folder | Run karne ki command |
|---|-----------|--------|----------------------|
| 1 | Private Key Guardian | c1 | `python key_guardian.py sample_secrets.txt --mask-output masked.txt` |
| 2 | Transaction Detective | c2 | `python tx_detective.py transactions.txt` (graph: tx_graph.png) |
| 3 | Reentrancy Detector | c3 | `python simulate_reentrancy.py` + Remix demo |
| 4 | Fake Token Detector | c4 | `python token_detector.py` |
| 5 | Phishing Detector | c5 | `python phishing_detector.py` (mockup: warning.html) |
| 6 | Smart Contract Auditor | c6 | `python vuln_scanner.py VulnerableVault.sol` + AUDIT_REPORT.md |
| 7 | AI vs Hacker | c7 | AI_vs_HUMAN_REPORT.md + `python test_ai_claims.py` |

Sab Python scripts ke liye sirf Python 3 chahiye (C2 graph ke liye `pip install matplotlib`).
Solidity files https://remix.ethereum.org par chalti hain (compile: 0.8.20+).

## Step-by-step: aap ko kya karna hai
**Step 1 (0-5 min):** Pata karo aap ki team ko kaun sa challenge mila. Us folder ko kholo.
**Step 2 (5-30 min):** Code chalao (command upar table mein), output samjho, code padh kar har function ka kaam yaad karo.
**Step 3 (30-38 min):** Test/attack karo: sample data se output dekho, apna naya input daal kar dobara run karo (jaise naya URL, naya token, naya TX).
Solidity challenges (3, 6, 7): Remix mein Vulnerable deploy karo -> Attack karo -> Secure deploy karo -> attack fail hota dikhao.
**Step 4 (38-45 min):** 2-minute live demo (neeche script).
**Step 5:** Bonus zaroor dikhao (masking, graph, nonReentrant, custom rules, warning mockup, scanner) - extra marks.

## Remix par Reentrancy demo (C3) - exact steps
1. Remix mein `VulnerableBank.sol`, `Attacker.sol`, `SecureBank.sol` paste karo, compile karo.
2. Account A se `VulnerableBank` deploy, phir `deposit` 10 ETH (value field mein 10 ether).
3. Account B se `Attacker(bankAddress)` deploy with value 1 ether, phir `attack()`.
4. `totalFunds()` = 0 aur `loot()` = 11 ETH -> bank drain ho gaya.
5. Yehi `SecureBank` ke saath: `attack()` revert hoga -> secure.

## 2-minute demo script (har challenge ke liye)
1. **Problem (20s):** "Humare paas ... problem thi (jaise exposed private keys)."
2. **Attack / Finding (30s):** "Is wajah se attacker ... kar sakta hai."
3. **Solution (30s):** "Humne ... algorithm/fix lagaya (regex, risk score, CEI)."
4. **Working output (30s):** Live run -> risk score aur warning dikhao.
5. **Lesson (10s):** "AI help karta hai magar validation insaan ko karni hai."

## Viva ke mumkin sawal
- Reentrancy kya hai? Checks-Effects-Interactions kyun? nonReentrant kaise kaam karta hai?
- Risk score kaise calculate hota hai? (har rule ke points, total max 100)
- Private key aur wallet address mein farq? (key = secret, address = public)
- tx.origin vs msg.sender? Solidity 0.8 mein overflow? `unchecked` ka kya matlab?
- AI ne kya galat/miss kiya aur aap ne kaise verify kiya?

## Final submission checklist (kuch miss na ho)
- [ ] Code run karke screenshots (har challenge ka output)
- [ ] C1: private keys + wallet + secrets detect, score 0-100, warning, masking (bonus)
- [ ] C2: parse, suspicious wallets, large transfers, risk score, alert, graph (bonus)
- [ ] C3: vulnerability + explanation + CEI fix + test + nonReentrant (bonus)
- [ ] C4: contract/symbol/name/owner/metadata/duplicates/unusual owner + custom rules (bonus)
- [ ] C5: HTTP, domain, keywords, urgency, scam words, long URL + warning mockup (bonus)
- [ ] C6: >=5 issues (8 diye hain) with Vulnerability -> Danger -> Attack -> Fix -> Secure code + scanner (bonus)
- [ ] C7: AI report + testing + >=2 AI mistakes (6 diye hain) + improved report
- [ ] Apni team ke naam, date, aur AI tool ka naam report mein likho; demo ek baar practice karo

Important: Apni team ka challenge samajh kar khud code padho - viva mein explain karna aap ki zimmedari hai.
