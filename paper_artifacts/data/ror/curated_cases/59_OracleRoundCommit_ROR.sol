// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracleSettlement59 {
    function settleRound59(uint256 roundId, uint256 price) external;
}

contract OracleRoundCommit59 {
    struct Round {
        uint256 price;
        uint256 timestamp;
        bool finalized;
    }

    mapping(uint256 => Round) public rounds;
    uint256 public latestRound;
    uint256 public latestPrice = 1e18;
    uint256 public committedPrice = 1e18;
    uint256 public maxDeviationBps = 2_000;
    address public reporter;

    event RoundCommitted(uint256 indexed roundId, uint256 price);

    constructor() {
        reporter = msg.sender;
    }

    function latestAnswer() external view returns (uint256) {
        return committedPrice;
    }

    function latestTimestamp() external view returns (uint256) {
        return rounds[latestRound].timestamp;
    }

    function pushRound(uint256 newPrice, address settlement) external {
        require(newPrice > 0, "BAD_PRICE");
        uint256 diff = newPrice > latestPrice ? newPrice - latestPrice : latestPrice - newPrice;
        require(diff * 10_000 <= latestPrice * maxDeviationBps, "DEVIATION");

        latestRound += 1;
        latestPrice = newPrice;
        committedPrice = newPrice;
        rounds[latestRound] = Round({price: newPrice, timestamp: block.timestamp, finalized: false});

        emit RoundCommitted(latestRound, committedPrice);
        IOracleSettlement59(settlement).settleRound59(latestRound, committedPrice);
    }
}

