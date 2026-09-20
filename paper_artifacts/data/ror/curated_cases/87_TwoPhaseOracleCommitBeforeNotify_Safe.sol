// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Notifier87 {
    function notifyOracleUpdate() external;
}

contract TwoPhaseOracleCommitBeforeNotifySafe87 {
    uint256 public pendingAnswer;
    uint256 public committedAnswer;
    Notifier87 public notifier;

    constructor(Notifier87 notifier_) {
        notifier = notifier_;
    }

    function stage(uint256 answer) external {
        pendingAnswer = answer;
    }

    function commit() external {
        committedAnswer = pendingAnswer;
        notifier.notifyOracleUpdate();
    }

    function latestAnswer() external view returns (uint256) {
        return committedAnswer;
    }
}
