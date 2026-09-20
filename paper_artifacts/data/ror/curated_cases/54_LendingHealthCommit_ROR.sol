// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDebtSettlement54 {
    function draw54(address borrower, uint256 amount, uint256 health) external;
}

contract LendingHealthCommit54 {
    struct Position {
        uint256 collateral;
        uint256 debt;
        uint256 healthIndexCache;
        bool borrowing;
    }

    mapping(address => Position) public positions;
    mapping(address => uint256) public healthIndexCache;
    uint256 public totalDebt;
    uint256 public totalCollateral;
    uint256 public minHealth = 1.1e18;
    uint256 public borrowFeeBps = 25;

    event BorrowCommitted(address indexed borrower, uint256 amount, uint256 health);

    function seed(address user, uint256 collateralAmount) external {
        positions[user].collateral = collateralAmount;
        positions[user].healthIndexCache = type(uint256).max;
        healthIndexCache[user] = type(uint256).max;
        totalCollateral += collateralAmount;
    }

    function accountHealth(address user) external view returns (uint256) {
        return healthIndexCache[user];
    }

    function availableBorrow(address user) external view returns (uint256) {
        Position storage position = positions[user];
        if (position.collateral <= position.debt) return 0;
        return (position.collateral - position.debt) / 2;
    }

    function _health(uint256 collateral, uint256 debt) internal pure returns (uint256) {
        if (debt == 0) return type(uint256).max;
        return collateral * 1e18 / debt;
    }

    function borrow(uint256 amount, address settlement) external {
        Position storage position = positions[msg.sender];
        require(amount > 0, "ZERO_AMOUNT");

        uint256 fee = amount * borrowFeeBps / 10_000;
        uint256 debtAfter = position.debt + amount + fee;
        uint256 healthAfter = _health(position.collateral, debtAfter);
        require(healthAfter >= minHealth, "LOW_HEALTH");

        position.debt = debtAfter;
        position.borrowing = true;
        position.healthIndexCache = healthAfter;
        healthIndexCache[msg.sender] = healthAfter;
        totalDebt += amount + fee;

        emit BorrowCommitted(msg.sender, amount, healthAfter);
        IDebtSettlement54(settlement).draw54(msg.sender, amount, healthAfter);
    }
}
