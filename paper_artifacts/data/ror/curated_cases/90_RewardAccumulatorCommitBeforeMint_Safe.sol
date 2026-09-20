// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface RewardMinter90 {
    function mint(address to, uint256 amount) external;
}

contract RewardAccumulatorCommitBeforeMintSafe90 {
    uint256 public rewardPerShare;
    RewardMinter90 public minter;

    constructor(RewardMinter90 minter_) {
        minter = minter_;
    }

    function harvest(address to, uint256 delta, uint256 amount) external {
        rewardPerShare += delta;
        minter.mint(to, amount);
    }

    function pendingReward(uint256 shares) external view returns (uint256) {
        return shares * rewardPerShare;
    }
}
