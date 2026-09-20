// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface SnapshotHook103 {
    function afterSnapshot() external;
}

contract SafePreviewUsesPostStateSnapshotSafe103 {
    uint256 public postStateAssets;
    uint256 public postStateShares;
    SnapshotHook103 public hook;

    constructor(SnapshotHook103 hook_) {
        hook = hook_;
    }

    function mutateAndCall(uint256 assets, uint256 shares) external {
        postStateAssets = assets;
        postStateShares = shares;
        hook.afterSnapshot();
    }

    function previewMint(uint256 shares) external view returns (uint256) {
        return postStateShares == 0 ? shares : (shares * postStateAssets) / postStateShares;
    }
}
