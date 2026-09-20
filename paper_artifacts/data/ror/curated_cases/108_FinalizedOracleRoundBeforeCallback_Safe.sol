// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Callback108 {
    function onFinalize() external;
}

contract FinalizedOracleRoundBeforeCallbackSafe108 {
    uint256 public latestRound;
    uint256 public latestPrice;
    Callback108 public callback;

    constructor(Callback108 callback_) {
        callback = callback_;
    }

    function finalizeRound(uint256 roundId, uint256 price) external {
        latestRound = roundId;
        latestPrice = price;
        callback.onFinalize();
    }

    function latest() external view returns (uint256, uint256) {
        return (latestRound, latestPrice);
    }
}
