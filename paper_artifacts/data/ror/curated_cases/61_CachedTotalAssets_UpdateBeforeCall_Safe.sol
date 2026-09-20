// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Strategy61 {
    function deposit(uint256 amount) external;
}

contract CachedTotalAssetsUpdateBeforeCallSafe61 {
    uint256 public cachedTotalAssets;
    uint256 public lastUpdateBlock;
    Strategy61 public strategy;

    constructor(Strategy61 strategy_) {
        strategy = strategy_;
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero amount");
        cachedTotalAssets += amount;
        lastUpdateBlock = block.number;
        strategy.deposit(amount);
    }

    function totalAssets() external view returns (uint256) {
        return cachedTotalAssets;
    }
}
