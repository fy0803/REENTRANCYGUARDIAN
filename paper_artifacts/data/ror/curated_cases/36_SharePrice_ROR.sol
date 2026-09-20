// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICallback36 {
    function onCallback36() external;
}

contract RORShareVault36 {
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
        ICallback36(msg.sender).onCallback36();
        totalAssets -= assets;
    }
}

contract RORShareLender36 {
    RORShareVault36 public immutable vault;
    mapping(address => uint256) public debt;

    constructor(RORShareVault36 vault_) {
        vault = vault_;
    }

    function borrow(uint256 collateralShares) external {
        debt[msg.sender] += collateralShares * vault.pricePerShare() / 2e18;
    }
}
