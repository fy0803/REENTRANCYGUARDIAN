// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface AccountingHook75 {
    function settle(uint256 amount) external;
}

contract ExternalCallNoReadableStateSafe75 {
    uint256 private internalAccumulator;
    AccountingHook75 public hook;

    constructor(AccountingHook75 hook_) {
        hook = hook_;
    }

    function settle(uint256 amount) external {
        hook.settle(amount);
        internalAccumulator += amount;
    }

    function publicStatus() external pure returns (bool) {
        return true;
    }
}
