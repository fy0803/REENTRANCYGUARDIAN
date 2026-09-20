// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface DepositHook66 {
    function onDeposit(address account, uint256 amount) external;
}

contract DepositWithReentrancyGuardSafe66 {
    bool private locked;
    uint256 public cachedAssets;
    DepositHook66 public hook;

    constructor(DepositHook66 hook_) {
        hook = hook_;
    }

    modifier nonReentrant() {
        require(!locked, "locked");
        locked = true;
        _;
        locked = false;
    }

    function deposit(uint256 amount) external nonReentrant {
        cachedAssets += amount;
        hook.onDeposit(msg.sender, amount);
    }

    function totalAssets() external view returns (uint256) {
        require(!locked, "updating");
        return cachedAssets;
    }
}
