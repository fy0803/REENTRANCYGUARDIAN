// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRateCallback48 {
    function onUnwrap48() external;
}

contract RORRateProviderToken48 {
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
        IRateCallback48(msg.sender).onUnwrap48();
        backingAssets -= shareAmount;
    }
}

contract RORRateBasedVault48 {
    RORRateProviderToken48 public immutable token;
    mapping(address => uint256) public credit;

    constructor(RORRateProviderToken48 token_) {
        token = token_;
    }

    function issueCredit(uint256 wrappedAmount) external {
        credit[msg.sender] += wrappedAmount * token.getRate() / 1e18;
    }
}
