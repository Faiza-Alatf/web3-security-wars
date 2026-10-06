# Challenge 7 – AI vs Blockchain Hacker
Contract analysed: `../c6/VulnerableVault.sol`
Prompt given to the AI: *"Analyze this Solidity smart contract and identify its security vulnerabilities."*

> NOTE FOR STUDENTS: Step 1 below is a SAMPLE AI answer showing a typical pattern. In your live session, paste the contract into your own AI assistant, replace Step 1 with its real output (screenshot/copy), and compare against the human findings in Step 4. Keep your real AI errors/misses in Step 3.

## Step 1 – AI Analysis (sample)
1. Reentrancy in `withdraw()` – HIGH
2. Missing access control on `setOwner()` – HIGH
3. Integer overflow in `addBonus()` – "not possible, Solidity 0.8+ has built-in overflow checks" – NONE
4. `deposit()` is vulnerable to reentrancy – MEDIUM
5. `send()` is safe because it only forwards 2300 gas – LOW

## Step 2 – Testing
| Test | Method | Result |
|------|--------|--------|
| Reentrancy in `withdraw` | Attacker contract (c3) in Remix | Confirmed – drained |
| `setOwner` | call from non-owner account | Confirmed – ownership taken |
| Overflow in `addBonus(3)` | `python test_ai_claims.py` / Remix | **3*100 wraps to 44** – AI wrong |
| Reentrancy in `deposit()` | inspect code: no external call | **No external call → AI false positive** |
| `send()` failure | send to contract with reverting fallback | Fails silently; balance still credited – AI wrong |
| `tx.origin`, `kill()`, unbounded loop | manual review / `vuln_scanner.py` | **AI missed all three** |

## Step 3 – AI Failures / Misses
1. **Incorrect (false negative):** said no overflow – but the `unchecked{}` block disables 0.8 protection; `uint8*100` wraps.
2. **Incorrect (false positive):** `deposit()` has no external call, so it cannot be re-entered.
3. **Incorrect reasoning:** `send()` being "safe" ignores that its return value is not checked.
4. **Missed:** `tx.origin` authentication (phishing attack).
5. **Missed:** unprotected `selfdestruct` in `kill()`.
6. **Missed:** unbounded loop DoS in `payAllDepositors()`.

## Step 4 – Improved Human Security Report
| Severity | Finding | Fix |
|----------|---------|-----|
| Critical | No access control `setOwner` | `onlyOwner` + 2-step transfer |
| Critical | Reentrancy `withdraw` | CEI + `nonReentrant` |
| Critical | Unprotected `selfdestruct` | remove |
| High | `tx.origin` auth | `msg.sender` |
| Medium | Unchecked `send` | checked `call` |
| Medium | `unchecked` overflow | remove unchecked, `uint256` |
| Medium | Unbounded loop | pagination |
| Low | Missing validation / events | `require`, events |
Secure code: `../c6/SecureVault.sol` (scanner: `python ../c6/vuln_scanner.py SecureVault.sol` → 0 issues).

## Key Lesson
AI can assist a security analyst – but it cannot replace security validation. Always test, never trust blindly.
