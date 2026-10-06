// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// SECURE version: Checks-Effects-Interactions + nonReentrant guard (bonus)
contract SecureBank {
    mapping(address => uint256) public balances;

    uint256 private _status = 1;               // 1 = not entered, 2 = entered
    modifier nonReentrant() {
        require(_status == 1, "ReentrancyGuard: reentrant call");
        _status = 2;
        _;
        _status = 1;
    }

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        // 1. CHECKS
        require(amount > 0, "amount = 0");
        require(balances[msg.sender] >= amount, "insufficient balance");
        // 2. EFFECTS (update state BEFORE sending ETH)
        balances[msg.sender] -= amount;
        // 3. INTERACTIONS
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function totalFunds() external view returns (uint256) {
        return address(this).balance;
    }
}
