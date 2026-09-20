// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRedeemObserver16 {
    function onRedeemPrepared16(address owner, uint256 assets) external;
}

contract RORShareVault16 {
    RORShareLedger16 public immutable ledger;

    constructor(RORShareLedger16 ledger_) {
        ledger = ledger_;
    }

    function seed(address user, uint256 userShares, uint256 assets) external {
        ledger.seed(user, userShares, assets);
    }

    function pricePerShare() external view returns (uint256) {
        return ledger.pricePerShare();
    }

    function withdraw(uint256 shareAmount, IRedeemObserver16 observer) external {
        uint256 assets = ledger.prepareWithdraw(msg.sender, shareAmount);
        observer.onRedeemPrepared16(msg.sender, assets);
        ledger.completeWithdraw(msg.sender, shareAmount, assets);
    }
}

contract RORShareLedger16 {
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

contract RORSharePriceConsumer16 {
    RORShareVault16 public immutable vault;
    mapping(address => uint256) public credit;

    constructor(RORShareVault16 vault_) {
        vault = vault_;
    }

    function draw(uint256 sharesIn) external {
        credit[msg.sender] += sharesIn * vault.pricePerShare() / 1e18;
    }
}
