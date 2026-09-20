// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISwapSettlement53 {
    function fill53(address trader, uint256 amountOut, uint256 quotedPrice) external;
}

contract SpotPriceCommit53 {
    struct PoolState {
        uint256 reserveIn;
        uint256 reserveOut;
        uint256 feeBps;
        uint256 lastTradeId;
    }

    mapping(address => uint256) public pendingOut;
    PoolState public pool = PoolState({
        reserveIn: 1_000 ether,
        reserveOut: 1_000 ether,
        feeBps: 30,
        lastTradeId: 0
    });
    uint256 public spotPriceCache = 1e18;
    uint256 public cumulativeQuotedOut;

    event SwapQuoted(address indexed trader, uint256 amountOut, uint256 price, uint256 tradeId);

    function seed(uint256 reserveIn_, uint256 reserveOut_) external {
        pool.reserveIn = reserveIn_;
        pool.reserveOut = reserveOut_;
        spotPriceCache = reserveIn_ * 1e18 / reserveOut_;
    }

    function spotPrice() external view returns (uint256) {
        return spotPriceCache;
    }

    function quoteAmountIn(uint256 amountOut) external view returns (uint256) {
        uint256 fee = amountOut * pool.feeBps / 10_000;
        return (amountOut + fee) * spotPriceCache / 1e18;
    }

    function quoteSwapOut(uint256 amountOut, address settlement) external {
        require(amountOut > 0 && amountOut < pool.reserveOut / 2, "BAD_OUT");

        pool.reserveOut -= amountOut;
        pool.lastTradeId += 1;
        pendingOut[msg.sender] += amountOut;
        cumulativeQuotedOut += amountOut;
        spotPriceCache = pool.reserveIn * 1e18 / pool.reserveOut;

        emit SwapQuoted(msg.sender, amountOut, spotPriceCache, pool.lastTradeId);
        ISwapSettlement53(settlement).fill53(msg.sender, amountOut, spotPriceCache);
    }
}

