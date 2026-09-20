// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface VaultAsset97 {
    function sendAsset(address to, uint256 amount) external;
}

contract WithdrawPreviewAfterAccountingCommitSafe97 {
    uint256 public totalAssetsCached;
    uint256 public totalShares;
    VaultAsset97 public asset;

    constructor(VaultAsset97 asset_) {
        asset = asset_;
    }

    function withdraw(address to, uint256 assets, uint256 shares) external {
        totalAssetsCached -= assets;
        totalShares -= shares;
        asset.sendAsset(to, assets);
    }

    function previewWithdraw(uint256 shares) external view returns (uint256) {
        return totalShares == 0 ? shares : (shares * totalAssetsCached) / totalShares;
    }
}
