// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// VULNERABLE - for education only
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);                 // 1. Check
        (bool success, ) = msg.sender.call{value: amount}("");   // 2. Interaction  <-- BEFORE state update
        require(success);
        balances[msg.sender] -= amount;                          // 3. Effect (too late!)
    }

    function totalFunds() public view returns (uint256) {
        return address(this).balance;
    }
}
