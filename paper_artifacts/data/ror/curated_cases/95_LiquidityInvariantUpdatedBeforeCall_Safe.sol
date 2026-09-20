// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface LiquidityHook95 {
    function afterLiquidityChange() external;
}

contract LiquidityInvariantUpdatedBeforeCallSafe95 {
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public invariantK;
    LiquidityHook95 public hook;

    constructor(LiquidityHook95 hook_) {
        hook = hook_;
    }

    function updateLiquidity(uint256 next0, uint256 next1) external {
        reserve0 = next0;
        reserve1 = next1;
        invariantK = next0 * next1;
        hook.afterLiquidityChange();
    }

    function spotInvariant() external view returns (uint256) {
        return invariantK;
    }
}
