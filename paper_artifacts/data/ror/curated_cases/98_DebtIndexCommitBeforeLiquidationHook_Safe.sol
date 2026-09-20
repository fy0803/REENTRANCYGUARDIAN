// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface LiquidationHook98 {
    function onLiquidation() external;
}

contract DebtIndexCommitBeforeLiquidationHookSafe98 {
    uint256 public debtIndex = 1e18;
    LiquidationHook98 public hook;

    constructor(LiquidationHook98 hook_) {
        hook = hook_;
    }

    function liquidate(uint256 nextDebtIndex) external {
        require(nextDebtIndex >= debtIndex, "bad index");
        debtIndex = nextDebtIndex;
        hook.onLiquidation();
    }

    function accountDebt(uint256 principal) external view returns (uint256) {
        return (principal * debtIndex) / 1e18;
    }
}
