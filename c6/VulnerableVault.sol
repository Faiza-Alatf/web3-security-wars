// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// VULNERABLE mini-vault for the audit challenge (educational)
contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;
    address[] public depositors;

    constructor() { owner = msg.sender; }

    // [V1] Access control: anyone can take ownership
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    // [V2] Missing validation: zero-value deposits, depositor list grows forever
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        depositors.push(msg.sender);
    }

    // [V3] Reentrancy + unsafe withdrawal logic (interaction before effect)
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }

    // [V4] tx.origin authentication -> phishing-contract attack
    function emergencyWithdraw(address payable to) public {
        require(tx.origin == owner);
        to.transfer(address(this).balance);
    }

    // [V5] Unchecked external call: failure is silently ignored
    function sendBonus(address payable user, uint256 amount) public {
        require(msg.sender == owner);
        user.send(amount);                  // return value ignored
        balances[user] += amount;           // accounting updated even if send failed
    }

    // [V6] Overflow-related: unchecked block disables 0.8 safety
    function addBonus(uint8 bonus) public {
        unchecked { balances[msg.sender] += bonus * 100; }   // uint8 * 100 wraps at 255
    }

    // [V7] Unbounded loop -> gas DoS
    function payAllDepositors() public {
        for (uint256 i = 0; i < depositors.length; i++) {
            balances[depositors[i]] += 1;
        }
    }

    // [V8] Weak ownership: anybody can destroy the contract? (no check at all)
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
