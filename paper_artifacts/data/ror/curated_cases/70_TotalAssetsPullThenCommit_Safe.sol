// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Strategy70 {
    function harvest() external returns (uint256);
}

contract TotalAssetsPullThenCommitSafe70 {
    uint256 public cachedTotalAssets;
    Strategy70 public strategy;

    constructor(Strategy70 strategy_) {
        strategy = strategy_;
    }

    function harvestAndCommit() external {
        uint256 harvested = strategy.harvest();
        cachedTotalAssets += harvested;
    }

    function totalAssets() external view returns (uint256) {
        return cachedTotalAssets;
    }
}
