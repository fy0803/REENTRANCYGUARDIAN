// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface CalculationHook76 {
    function execute(uint256 amount) external;
}

contract ReadOnlyPureCalculationSafe76 {
    uint256 public scale = 1e18;
    CalculationHook76 public hook;

    constructor(CalculationHook76 hook_) {
        hook = hook_;
    }

    function execute(uint256 amount) external {
        hook.execute(amount);
    }

    function quote(uint256 amount) external view returns (uint256) {
        return amount * scale;
    }
}
