// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface OracleHook81 {
    function afterCommit() external;
}

contract OracleCacheCommitBeforeHookSafe81 {
    uint256 public cachedPrice;
    uint256 public committedAt;
    OracleHook81 public hook;

    constructor(OracleHook81 hook_) {
        hook = hook_;
    }

    function publish(uint256 price) external {
        require(price > 0, "zero price");
        cachedPrice = price;
        committedAt = block.number;
        hook.afterCommit();
    }

    function latestPrice() external view returns (uint256) {
        return cachedPrice;
    }
}
