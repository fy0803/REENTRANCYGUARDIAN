// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface RoundHook100 {
    function onRoundUpdate() external;
}

contract PriceReadRequiresFinalizedRoundSafe100 {
    uint256 public currentRound;
    uint256 public finalizedRound;
    mapping(uint256 => uint256) public roundPrice;
    RoundHook100 public hook;

    constructor(RoundHook100 hook_) {
        hook = hook_;
    }

    function updateRound(uint256 roundId, uint256 price) external {
        currentRound = roundId;
        roundPrice[roundId] = price;
        finalizedRound = roundId;
        hook.onRoundUpdate();
    }

    function latestPrice() external view returns (uint256) {
        return roundPrice[finalizedRound];
    }
}
