// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// FIXED version of VulnerableVault
contract SecureVault {
    address public owner;
    address public pendingOwner;
    mapping(address => uint256) public balances;
    mapping(address => bool) private isDepositor;
    address[] public depositors;
    uint256 private _status = 1;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier nonReentrant() {
        require(_status == 1, "reentrant");
        _status = 2; _; _status = 1;
    }

    constructor() { owner = msg.sender; }

    // [F1] Two-step ownership transfer + access control
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender; pendingOwner = address(0);
    }

    // [F2] Validation + no duplicate depositor entries
    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        if (!isDepositor[msg.sender]) { isDepositor[msg.sender] = true; depositors.push(msg.sender); }
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // [F3] Checks-Effects-Interactions + nonReentrant
    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0 && balances[msg.sender] >= amount, "bad amount");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    // [F4] msg.sender instead of tx.origin, checked call
    function emergencyWithdraw(address payable to) external onlyOwner nonReentrant {
        require(to != address(0), "zero address");
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "transfer failed");
    }

    // [F5] Unchecked call fixed: separate bonus pool + checked low-level call
    uint256 public bonusPool;
    uint256 public constant MAX_BONUS = 1 ether;
    function fundBonusPool() external payable onlyOwner { bonusPool += msg.value; }

    function sendBonus(address payable user, uint256 amount) external onlyOwner nonReentrant {
        require(user != address(0) && amount > 0 && amount <= MAX_BONUS, "invalid");
        require(amount <= bonusPool, "pool too small");
        bonusPool -= amount;
        (bool ok, ) = user.call{value: amount}("");
        require(ok, "send failed");
    }

    // [F6] Overflow fixed: uint256, checked math (no unchecked block), capped, owner-only, pool-backed
    function addBonus(address user, uint256 bonus) external onlyOwner {
        require(user != address(0) && bonus > 0 && bonus <= MAX_BONUS && bonus <= bonusPool, "bad bonus");
        bonusPool -= bonus;
        balances[user] += bonus;
    }

    // [F7] Unbounded loop fixed: paginated batches, pool-backed
    function creditDepositors(uint256 start, uint256 end, uint256 amountEach) external onlyOwner {
        if (end > depositors.length) end = depositors.length;
        require(start < end, "empty range");
        uint256 cost = amountEach * (end - start);
        require(cost <= bonusPool, "pool too small");
        bonusPool -= cost;
        for (uint256 i = start; i < end; i++) balances[depositors[i]] += amountEach;
    }

    // [F8] kill()/selfdestruct removed entirely (deprecated, EIP-6780). Plain ETH transfers rejected:
    receive() external payable { revert("use deposit()"); }
}
