// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface RateRefresher78 {
    function refresh() external;
}

contract CachedRateExpiresDuringCallSafe78 {
    uint256 public cachedRate = 1e18;
    uint256 public validUntil;
    RateRefresher78 public refresher;

    constructor(RateRefresher78 refresher_) {
        refresher = refresher_;
    }

    function refreshRate(uint256 newRate) external {
        validUntil = block.timestamp;
        refresher.refresh();
        cachedRate = newRate;
        validUntil = block.timestamp + 1 hours;
    }

    function getRate() external view returns (uint256) {
        require(block.timestamp <= validUntil, "rate expired");
        return cachedRate;
    }
}
