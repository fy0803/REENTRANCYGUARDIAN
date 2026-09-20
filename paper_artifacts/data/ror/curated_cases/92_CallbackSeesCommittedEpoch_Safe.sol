// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface EpochHook92 {
    function onEpochClosed() external;
}

contract CallbackSeesCommittedEpochSafe92 {
    uint256 public finalizedEpoch;
    uint256 public finalizedValue;
    EpochHook92 public hook;

    constructor(EpochHook92 hook_) {
        hook = hook_;
    }

    function closeEpoch(uint256 epoch, uint256 value) external {
        finalizedEpoch = epoch;
        finalizedValue = value;
        hook.onEpochClosed();
    }

    function latestFinalizedValue() external view returns (uint256) {
        return finalizedValue;
    }
}
