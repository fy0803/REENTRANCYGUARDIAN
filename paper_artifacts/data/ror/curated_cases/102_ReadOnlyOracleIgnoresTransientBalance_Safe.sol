// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface BalanceHook102 {
    function afterTransfer() external;
}

contract ReadOnlyOracleIgnoresTransientBalanceSafe102 {
    uint256 public lastCommittedPrice;
    BalanceHook102 public hook;

    constructor(BalanceHook102 hook_) {
        hook = hook_;
    }

    function externalTransfer() external {
        hook.afterTransfer();
    }

    function commitPrice(uint256 price) external {
        lastCommittedPrice = price;
    }

    function consult() external view returns (uint256) {
        return lastCommittedPrice;
    }
}
