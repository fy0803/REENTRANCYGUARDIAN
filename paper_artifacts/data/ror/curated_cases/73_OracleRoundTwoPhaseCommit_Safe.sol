// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface RoundHook73 {
    function beforeCommit(uint256 answer) external;
}

contract OracleRoundTwoPhaseCommitSafe73 {
    uint256 public committedAnswer = 1e18;
    uint256 public committedRound;
    RoundHook73 public hook;

    constructor(RoundHook73 hook_) {
        hook = hook_;
    }

    function pushRound(uint256 answer) external {
        hook.beforeCommit(answer);
        committedAnswer = answer;
        committedRound += 1;
    }

    function latestAnswer() external view returns (uint256) {
        return committedAnswer;
    }
}
