// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface JoinHook85 {
    function onJoin() external;
}

contract VirtualPriceLockDuringJoinSafe85 {
    uint256 public virtualPrice = 1e18;
    bool private readLocked;
    JoinHook85 public hook;

    constructor(JoinHook85 hook_) {
        hook = hook_;
    }

    function join(uint256 newPrice) external {
        readLocked = true;
        virtualPrice = newPrice;
        hook.onJoin();
        readLocked = false;
    }

    function getVirtualPrice() external view returns (uint256) {
        require(!readLocked, "read locked");
        return virtualPrice;
    }
}
