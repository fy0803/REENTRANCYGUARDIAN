// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface ExternalRate84 {
    function sync() external;
}

contract RateProviderNoMidCallMutationSafe84 {
    uint256 public rate = 1e18;
    ExternalRate84 public provider;

    constructor(ExternalRate84 provider_) {
        provider = provider_;
    }

    function refresh() external {
        uint256 stableRate = rate;
        provider.sync();
        require(rate == stableRate, "rate changed during refresh");
    }

    function getRate() external view returns (uint256) {
        return rate;
    }
}
