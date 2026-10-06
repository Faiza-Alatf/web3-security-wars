"""Challenge 7 - verifying the AI's claims by testing (simulation of EVM uint8 arithmetic).
Confirm the same thing live in Remix with VulnerableVault.addBonus(3)."""
def addBonus_unchecked(bonus_uint8):   # uint8 * 100 inside unchecked -> wraps mod 256
    return (bonus_uint8 * 100) % 256
def addBonus_checked(bonus_uint8):
    r = bonus_uint8 * 100
    if r > 255: raise OverflowError('Panic(0x11) arithmetic overflow')
    return r
print('AI CLAIM: "No overflow possible, Solidity 0.8 has built-in checks"')
print('  unchecked addBonus(3)  ->', addBonus_unchecked(3), '(expected 300) => CLAIM IS WRONG')
try: addBonus_checked(3)
except OverflowError as e: print('  checked   addBonus(3)  ->', e, '(would revert; unchecked{} removed that safety)')
