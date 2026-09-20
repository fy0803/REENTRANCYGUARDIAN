// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface PhaseHook93 {
    function duringUpdate() external;
}

contract ReentrantReadBlockedByPhaseSafe93 {
    enum Phase {
        Idle,
        Updating
    }

    Phase public phase;
    uint256 public cachedValue;
    PhaseHook93 public hook;

    constructor(PhaseHook93 hook_) {
        hook = hook_;
    }

    function update(uint256 value) external {
        phase = Phase.Updating;
        cachedValue = value;
        hook.duringUpdate();
        phase = Phase.Idle;
    }

    function readValue() external view returns (uint256) {
        require(phase == Phase.Idle, "updating");
        return cachedValue;
    }
}
