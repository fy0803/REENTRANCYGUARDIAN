// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Notify113 {
    function notifyRate() external;
}

contract StableRateSnapshotBeforeNotifySafe113 {
    uint256 public stableRateSnapshot;
    Notify113 public notifier;

    constructor(Notify113 notifier_) {
        notifier = notifier_;
    }

    function snapshotAndNotify(uint256 rate) external {
        stableRateSnapshot = rate;
        notifier.notifyRate();
    }

    function stableRate() external view returns (uint256) {
        return stableRateSnapshot;
    }
}
