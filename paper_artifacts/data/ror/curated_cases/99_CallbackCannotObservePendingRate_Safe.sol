// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface PendingRateHook99 {
    function afterStage() external;
}

contract CallbackCannotObservePendingRateSafe99 {
    uint256 private pendingRate;
    uint256 public committedRate = 1e18;
    PendingRateHook99 public hook;

    constructor(PendingRateHook99 hook_) {
        hook = hook_;
    }

    function stageRate(uint256 rate) external {
        pendingRate = rate;
        hook.afterStage();
    }

    function commitRate() external {
        committedRate = pendingRate;
    }

    function getRate() external view returns (uint256) {
        return committedRate;
    }
}
