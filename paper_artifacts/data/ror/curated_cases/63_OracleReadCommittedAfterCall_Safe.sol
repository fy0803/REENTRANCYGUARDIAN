// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface OracleConsumer63 {
    function notify(uint256 roundId) external;
}

contract OracleReadCommittedAfterCallSafe63 {
    uint256 private pendingAnswer;
    uint256 private committedAnswer;
    uint256 public roundId;
    OracleConsumer63 public consumer;

    constructor(OracleConsumer63 consumer_) {
        consumer = consumer_;
        committedAnswer = 1e18;
    }

    function pushRound(uint256 answer) external {
        pendingAnswer = answer;
        consumer.notify(roundId + 1);
        committedAnswer = pendingAnswer;
        roundId += 1;
    }

    function latestAnswer() external view returns (uint256) {
        return committedAnswer;
    }
}
