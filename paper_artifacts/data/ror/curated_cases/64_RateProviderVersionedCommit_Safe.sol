// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface RateHook64 {
    function afterRateCommit(uint256 version) external;
}

contract RateProviderVersionedCommitSafe64 {
    uint256 public committedRate = 1e18;
    uint256 public committedVersion;
    RateHook64 public hook;

    constructor(RateHook64 hook_) {
        hook = hook_;
    }

    function updateRate(uint256 newRate) external {
        committedRate = newRate;
        committedVersion += 1;
        hook.afterRateCommit(committedVersion);
    }

    function getRate() external view returns (uint256 rate, uint256 version) {
        return (committedRate, committedVersion);
    }
}
