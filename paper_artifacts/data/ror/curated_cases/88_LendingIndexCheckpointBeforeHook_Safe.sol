// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface LendingHook88 {
    function afterCheckpoint() external;
}

contract LendingIndexCheckpointBeforeHookSafe88 {
    uint256 public borrowIndex = 1e18;
    uint256 public checkpointBlock;
    LendingHook88 public hook;

    constructor(LendingHook88 hook_) {
        hook = hook_;
    }

    function checkpoint(uint256 nextIndex) external {
        require(nextIndex >= borrowIndex, "index regression");
        borrowIndex = nextIndex;
        checkpointBlock = block.number;
        hook.afterCheckpoint();
    }

    function currentBorrowIndex() external view returns (uint256) {
        return borrowIndex;
    }
}
