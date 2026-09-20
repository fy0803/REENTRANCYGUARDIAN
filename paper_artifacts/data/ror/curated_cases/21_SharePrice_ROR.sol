// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRedeemObserver21 {
    function onRedeemPrepared21(address owner, uint256 assets) external;
}

contract RORShareVault21 {
    RORShareLedger21 public immutable ledger;

    constructor(RORShareLedger21 ledger_) {
        ledger = ledger_;
    }

    function seed(address user, uint256 userShares, uint256 assets) external {
        ledger.seed(user, userShares, assets);
    }

    function pricePerShare() external view returns (uint256) {
        return ledger.pricePerShare();
    }

    function withdraw(uint256 shareAmount, IRedeemObserver21 observer) external {
        uint256 assets = ledger.prepareWithdraw(msg.sender, shareAmount);
        observer.onRedeemPrepared21(msg.sender, assets);
        ledger.completeWithdraw(msg.sender, shareAmount, assets);
    }
}

contract RORShareLedger21 {
    mapping(address => uint256) public shares;
    mapping(address => uint256) public preparedAssets;
    uint256 public totalShares;
    uint256 public totalAssets;
    uint256 public preparedTotal;

    function seed(address user, uint256 userShares, uint256 assets) external {
        shares[user] = userShares;
        totalShares = userShares;
        totalAssets = assets;
    }

    function pricePerShare() external view returns (uint256) {
        return (totalAssets - preparedTotal) * 1e18 / totalShares;
    }

    function prepareWithdraw(address owner, uint256 shareAmount) external returns (uint256 assets) {
        uint256 assets = shareAmount * totalAssets / totalShares;
        preparedAssets[owner] += assets;
        preparedTotal += assets;
        return assets;
    }

    function completeWithdraw(address owner, uint256 shareAmount, uint256 assets) external {
        preparedAssets[owner] -= assets;
        preparedTotal -= assets;
        shares[owner] -= shareAmount;
        totalShares -= shareAmount;
        totalAssets -= assets;
    }
}

contract RORSharePriceConsumer21 {
    RORShareVault21 public immutable vault;
    mapping(address => uint256) public credit;

    constructor(RORShareVault21 vault_) {
        vault = vault_;
    }

    function draw(uint256 sharesIn) external {
        credit[msg.sender] += sharesIn * vault.pricePerShare() / 1e18;
    }
}
