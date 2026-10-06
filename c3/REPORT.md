# Challenge 3 – Reentrancy Attack Detector

## 1. Vulnerability
`withdraw()` sends ETH (`msg.sender.call{value: amount}("")`) **before** reducing `balances[msg.sender]`.
Order used: Check → Interaction → Effect (WRONG).

## 2. How reentrancy occurs
1. Attacker contract deposits 1 ETH → `balances[attacker] = 1`.
2. Attacker calls `withdraw(1)`. Check passes (1 >= 1).
3. Bank sends 1 ETH → attacker's `receive()` runs.
4. Inside `receive()`, attacker calls `withdraw(1)` **again**. Balance is still 1 (not yet reduced) → check passes again.
5. Repeats until the bank is empty. Only then do the `-=` lines run (each fires in the unwinding stack).
Result: attacker deposits 1 ETH and drains everyone's funds (simulation: took 21 ETH from a 21 ETH bank).

## 3. Fix – Checks-Effects-Interactions
```
Check  -> require(balances[msg.sender] >= amount)
Effect -> balances[msg.sender] -= amount
Interact -> msg.sender.call{value: amount}("")
```
Now a re-entrant call sees the already-reduced balance and `require` fails.

## 4. Bonus – nonReentrant guard
A `_status` lock (1/2) set at function start and reset at the end; any nested call reverts.

## 5. Testing
- `python simulate_reentrancy.py` -> vulnerable bank drained, secure bank safe (PASSED).
- Remix test (live demo): deploy `VulnerableBank`, deposit 10 ETH from account 2, deploy `Attacker(bankAddress)` with 1 ETH, call `attack()`, check `totalFunds()` = 0 and `loot()` = 11 ETH. Repeat on `SecureBank` -> `attack()` reverts.
- All three .sol files compile with solc 0.8.24.
