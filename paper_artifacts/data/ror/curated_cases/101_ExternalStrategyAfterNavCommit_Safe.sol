// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Strategy101 {
    function rebalance() external;
}

contract ExternalStrategyAfterNavCommitSafe101 {
    uint256 public netAssetValue;
    Strategy101 public strategy;

    constructor(Strategy101 strategy_) {
        strategy = strategy_;
    }

    function rebalance(uint256 nextNav) external {
        netAssetValue = nextNav;
        strategy.rebalance();
    }

    function nav() external view returns (uint256) {
        return netAssetValue;
    }
}
