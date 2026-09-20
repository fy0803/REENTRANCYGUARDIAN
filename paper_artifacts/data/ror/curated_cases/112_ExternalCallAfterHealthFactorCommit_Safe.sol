// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface HealthHook112 {
    function afterHealthUpdate() external;
}

contract ExternalCallAfterHealthFactorCommitSafe112 {
    mapping(address => uint256) public healthFactor;
    HealthHook112 public hook;

    constructor(HealthHook112 hook_) {
        hook = hook_;
    }

    function updateHealth(address account, uint256 factor) external {
        healthFactor[account] = factor;
        hook.afterHealthUpdate();
    }

    function getHealthFactor(address account) external view returns (uint256) {
        return healthFactor[account];
    }
}
