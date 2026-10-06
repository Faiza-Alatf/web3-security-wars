# Challenge 6 – Mini Security Audit: `VulnerableVault.sol`
Format for every finding: **Vulnerability → Why dangerous → Attack scenario → Fix → Secure code** (full code in `SecureVault.sol`).

| # | Issue | Severity |
|---|-------|----------|
| V1 | Missing access control on `setOwner` | Critical |
| V2 | Reentrancy / unsafe withdrawal in `withdraw` | Critical |
| V3 | `tx.origin` authentication in `emergencyWithdraw` | High |
| V4 | Unchecked external call (`send`) in `sendBonus` | Medium |
| V5 | Overflow via `unchecked` block in `addBonus` | Medium |
| V6 | Unbounded loop (gas DoS) in `payAllDepositors` | Medium |
| V7 | Unprotected `selfdestruct` in `kill` | Critical |
| V8 | Missing validation in `deposit` (zero value, duplicate depositors) | Low |

---
### V1 Missing access control – `setOwner`
- **Why dangerous:** anyone can become owner and then call every owner-only function.
- **Attack:** attacker calls `setOwner(attacker)` → `emergencyWithdraw(attacker)` → vault drained.
- **Fix:** `onlyOwner` modifier + two-step ownership transfer + zero-address check.
```solidity
function transferOwnership(address n) external onlyOwner { require(n != address(0)); pendingOwner = n; }
function acceptOwnership() external { require(msg.sender == pendingOwner); owner = msg.sender; pendingOwner = address(0); }
```

### V2 Reentrancy / unsafe withdrawal – `withdraw`
- **Why dangerous:** ETH is sent before the balance is reduced.
- **Attack:** malicious contract re-enters `withdraw` from `receive()` (see Challenge 3).
- **Fix:** Checks-Effects-Interactions + `nonReentrant`.
```solidity
function withdraw(uint256 a) external nonReentrant {
    require(a > 0 && balances[msg.sender] >= a);
    balances[msg.sender] -= a;
    (bool ok,) = msg.sender.call{value: a}(""); require(ok);
}
```

### V3 `tx.origin` authentication – `emergencyWithdraw`
- **Why dangerous:** `tx.origin` is the original EOA, not the direct caller.
- **Attack:** owner is tricked into calling a malicious contract (phishing / fake airdrop); that contract calls `emergencyWithdraw(attacker)`; `tx.origin == owner` is true → funds stolen.
- **Fix:** use `msg.sender` via `onlyOwner`.
```solidity
function emergencyWithdraw(address payable to) external onlyOwner nonReentrant { ... }
```

### V4 Unchecked external call – `sendBonus`
- **Why dangerous:** `send` returns false on failure (2300 gas stipend); return value ignored but `balances[user]` is still credited → accounting mismatch / free balance.
- **Attack:** user is a contract whose fallback reverts; send fails silently, user still gets credited balance and withdraws it, using other users' funds.
- **Fix:** checked `call`, separate bonus pool, cap, `onlyOwner`.
```solidity
(bool ok,) = user.call{value: amount}(""); require(ok, "send failed");
```

### V5 Overflow with `unchecked` – `addBonus`
- **Why dangerous:** Solidity ≥0.8 reverts on overflow, but `unchecked {}` turns that protection off; `uint8 bonus * 100` wraps modulo 256.
- **Attack:** `addBonus(3)` → 3*100=300 → wraps to 44, wrong accounting; attacker picks values to get predictable wrong amounts. Also, anyone can call it → free balance.
- **Fix:** remove `unchecked`, use `uint256`, add `onlyOwner`, cap, and back by a pool.
```solidity
function addBonus(address u, uint256 b) external onlyOwner { require(b <= MAX_BONUS && b <= bonusPool); bonusPool -= b; balances[u] += b; }
```

### V6 Unbounded loop – `payAllDepositors`
- **Why dangerous:** the `depositors` array only grows (duplicates allowed); loop gas grows until it exceeds the block gas limit → function permanently unusable (DoS).
- **Attack:** attacker calls `deposit()` thousands of times with 1 wei.
- **Fix:** paginate (`start`, `end`), de-duplicate depositors.
```solidity
function creditDepositors(uint256 s, uint256 e, uint256 each) external onlyOwner { ... }
```

### V7 Unprotected `selfdestruct` – `kill`
- **Why dangerous:** any caller can destroy the contract and receive all ETH.
- **Attack:** `kill()` from any account → balance sent to attacker.
- **Fix:** remove entirely (selfdestruct is deprecated, EIP-6780); use pausable/upgrade patterns instead.

### V8 Missing validation – `deposit`
- **Why dangerous:** zero-value deposits push garbage entries (feeds V6); no events for off-chain monitoring.
- **Fix:** `require(msg.value > 0)`, track `isDepositor`, emit `Deposited`.
