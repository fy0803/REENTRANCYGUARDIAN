// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface LiquidationHook69 {
    function afterLiquidation(address borrower) external;
}

contract LendingHealthFinalizedBeforeCallSafe69 {
    mapping(address => uint256) public debt;
    mapping(address => uint256) public collateral;
    LiquidationHook69 public hook;

    constructor(LiquidationHook69 hook_) {
        hook = hook_;
    }

    function setPosition(address borrower, uint256 collateral_, uint256 debt_) external {
        collateral[borrower] = collateral_;
        debt[borrower] = debt_;
    }

    function liquidate(address borrower, uint256 repay) external {
        require(debt[borrower] >= repay, "too much repay");
        debt[borrower] -= repay;
        collateral[borrower] -= repay / 2;
        hook.afterLiquidation(borrower);
    }

    function healthFactor(address borrower) external view returns (uint256) {
        if (debt[borrower] == 0) return type(uint256).max;
        return (collateral[borrower] * 1e18) / debt[borrower];
    }
}
