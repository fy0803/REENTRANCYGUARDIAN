// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUnwrapObserver18 {
    function onUnwrapStaged18(address owner, uint256 assets) external;
}

contract RORRateProviderToken18 {
    RORRateLedger18 public immutable ledger;

    constructor(RORRateLedger18 ledger_) {
        ledger = ledger_;
    }

    function seed(address user, uint256 userShares, uint256 backing) external {
        ledger.seed(user, userShares, backing);
    }

    function getRate() external view returns (uint256) {
        return ledger.getRate();
    }

    function unwrap(uint256 shareAmount, IUnwrapObserver18 observer) external {
        uint256 assets = ledger.stageUnwrap(msg.sender, shareAmount);
        observer.onUnwrapStaged18(msg.sender, assets);
        ledger.commitUnwrap(msg.sender, shareAmount, assets);
    }
}

contract RORRateLedger18 {
    mapping(address => uint256) public shares;
    mapping(address => uint256) public stagedShares;
    uint256 public totalSupply;
    uint256 public backingAssets;
    uint256 public stagedAssets;

    function seed(address user, uint256 userShares, uint256 backing) external {
        shares[user] = userShares;
        totalSupply = userShares;
        backingAssets = backing;
    }

    function getRate() external view returns (uint256) {
        return (backingAssets - stagedAssets) * 1e18 / totalSupply;
    }

    function stageUnwrap(address owner, uint256 shareAmount) external returns (uint256 assets) {
        uint256 assets = shareAmount * backingAssets / totalSupply;
        stagedShares[owner] += shareAmount;
        stagedAssets += assets;
        return assets;
    }

    function commitUnwrap(address owner, uint256 shareAmount, uint256 assets) external {
        stagedShares[owner] -= shareAmount;
        stagedAssets -= assets;
        shares[owner] -= shareAmount;
        totalSupply -= shareAmount;
        backingAssets -= assets;
    }
}

contract RORRateBasedVault18 {
    RORRateProviderToken18 public immutable token;
    mapping(address => uint256) public credit;

    constructor(RORRateProviderToken18 token_) {
        token = token_;
    }

    function issueCredit(uint256 wrappedAmount) external {
        credit[msg.sender] += wrappedAmount * token.getRate() / 1e18;
    }
}
