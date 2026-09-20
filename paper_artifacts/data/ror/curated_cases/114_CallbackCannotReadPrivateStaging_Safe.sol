// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface StagingHook114 {
    function afterStage() external;
}

contract CallbackCannotReadPrivateStagingSafe114 {
    uint256 private stagedValue;
    uint256 public committedValue;
    StagingHook114 public hook;

    constructor(StagingHook114 hook_) {
        hook = hook_;
    }

    function stage(uint256 value) external {
        stagedValue = value;
        hook.afterStage();
    }

    function commit() external {
        committedValue = stagedValue;
    }

    function readCommitted() external view returns (uint256) {
        return committedValue;
    }
}
