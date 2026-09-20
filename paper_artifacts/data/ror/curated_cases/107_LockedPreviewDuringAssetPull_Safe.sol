// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface PullAsset107 {
    function pull(uint256 amount) external;
}

contract LockedPreviewDuringAssetPullSafe107 {
    bool private pulling;
    uint256 public totalAssetsCached;
    PullAsset107 public asset;

    constructor(PullAsset107 asset_) {
        asset = asset_;
    }

    function deposit(uint256 amount) external {
        pulling = true;
        asset.pull(amount);
        totalAssetsCached += amount;
        pulling = false;
    }

    function previewDeposit(uint256 amount) external view returns (uint256) {
        require(!pulling, "pulling");
        return amount;
    }
}
