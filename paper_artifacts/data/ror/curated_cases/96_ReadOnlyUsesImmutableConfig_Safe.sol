// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface ConfigHook96 {
    function ping() external;
}

contract ReadOnlyUsesImmutableConfigSafe96 {
    uint256 public immutable baseRate;
    ConfigHook96 public hook;

    constructor(uint256 baseRate_, ConfigHook96 hook_) {
        baseRate = baseRate_;
        hook = hook_;
    }

    function executeExternal() external {
        hook.ping();
    }

    function quote(uint256 amount) external view returns (uint256) {
        return amount * baseRate;
    }
}
