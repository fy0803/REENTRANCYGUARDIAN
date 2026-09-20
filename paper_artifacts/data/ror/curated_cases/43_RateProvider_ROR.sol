// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRateCallback43 {
    function onUnwrap43() external;
}

contract RORRateProviderToken43 {
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
        IRateCallback43(msg.sender).onUnwrap43();
        backingAssets -= shareAmount;
    }
}

contract RORRateBasedVault43 {
    RORRateProviderToken43 public immutable token;
    mapping(address => uint256) public credit;

    constructor(RORRateProviderToken43 token_) {
        token = token_;
    }

    function issueCredit(uint256 wrappedAmount) external {
        credit[msg.sender] += wrappedAmount * token.getRate() / 1e18;
    }
}
