// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface SwapHook68 {
    function afterSwap(uint256 amountIn) external;
}

contract SpotPriceSnapshotBeforeCallSafe68 {
    uint256 public reserve0 = 1_000 ether;
    uint256 public reserve1 = 2_000 ether;
    uint256 public lastPrice = 2e18;
    SwapHook68 public hook;

    constructor(SwapHook68 hook_) {
        hook = hook_;
    }

    function swap(uint256 amountIn) external {
        reserve0 += amountIn;
        reserve1 -= amountIn / 2;
        lastPrice = (reserve1 * 1e18) / reserve0;
        hook.afterSwap(amountIn);
    }

    function spotPrice() external view returns (uint256) {
        return lastPrice;
    }
}
