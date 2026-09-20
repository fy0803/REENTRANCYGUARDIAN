// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface ExternalOracle80 {
    function latestAnswer() external view returns (uint256);
}

interface OracleHook80 {
    function afterUpdate() external;
}

contract SafeExternalOracleAdapter80 {
    uint256 public cachedAnswer;
    ExternalOracle80 public oracle;
    OracleHook80 public hook;

    constructor(ExternalOracle80 oracle_, OracleHook80 hook_) {
        oracle = oracle_;
        hook = hook_;
    }

    function update() external {
        uint256 answer = oracle.latestAnswer();
        cachedAnswer = answer;
        hook.afterUpdate();
    }

    function latestAnswer() external view returns (uint256) {
        return cachedAnswer;
    }
}
