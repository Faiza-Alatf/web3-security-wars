"""Python simulation of the attack (tests BOTH contracts without a blockchain).
Run: python simulate_reentrancy.py
"""
class Bank:
    def __init__(self, secure):
        self.balances, self.eth, self.secure, self.locked = {}, 0, secure, False
    def deposit(self, who, amt):
        self.balances[who] = self.balances.get(who, 0) + amt; self.eth += amt
    def withdraw(self, who, amt, callback):
        if self.secure:                                   # nonReentrant
            if self.locked: raise Exception('ReentrancyGuard: reentrant call')
            self.locked = True
        assert self.balances.get(who, 0) >= amt, 'insufficient balance'   # CHECK
        if self.secure:
            self.balances[who] -= amt                     # EFFECT first
        self.eth -= amt; callback(amt)                    # INTERACTION (attacker's receive())
        if not self.secure:
            self.balances[who] -= amt                     # EFFECT last (vulnerable)
        if self.secure: self.locked = False

def run(secure):
    bank = Bank(secure)
    bank.deposit('victim1', 10); bank.deposit('victim2', 10)      # 20 ETH of honest funds
    stolen = {'v': 0}
    def receive(amt):
        stolen['v'] += amt
        if bank.eth >= 1:
            bank.withdraw('attacker', 1, receive)
    bank.deposit('attacker', 1)
    try:
        bank.withdraw('attacker', 1, receive)
    except Exception as e:
        print('   attack blocked ->', e)
    print(f"   attacker put in 1 ETH, took out {stolen['v']} ETH | bank left with {bank.eth} ETH")
    return stolen['v']

print('VULNERABLE BANK:'); a = run(False)
print('SECURE BANK:');     b = run(True)
assert a > 1 and b <= 1
print('\nTEST PASSED: vulnerable bank drained, secure bank safe.')
