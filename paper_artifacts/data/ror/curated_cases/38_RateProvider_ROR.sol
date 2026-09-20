// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRateCallback38 {
    function onUnwrap38() external;
}

contract RORRateProviderToken38 {
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
        IRateCallback38(msg.sender).onUnwrap38();
        backingAssets -= shareAmount;
    }
}

contract RORRateBasedVault38 {
    RORRateProviderToken38 public immutable token;
    mapping(address => uint256) public credit;

    constructor(RORRateProviderToken38 token_) {
        token = token_;
    }

    function issueCredit(uint256 wrappedAmount) external {
        credit[msg.sender] += wrappedAmount * token.getRate() / 1e18;
    }
}
