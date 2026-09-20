// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface SwapRouter91 {
    function swap(uint256 amountIn) external returns (uint256);
}

contract StableAssetRatioCommitBeforeSwapSafe91 {
    uint256 public assetRatio = 1e18;
    SwapRouter91 public router;

    constructor(SwapRouter91 router_) {
        router = router_;
    }

    function rebalance(uint256 nextRatio, uint256 amountIn) external {
        assetRatio = nextRatio;
        router.swap(amountIn);
    }

    function getAssetRatio() external view returns (uint256) {
        return assetRatio;
    }
}
