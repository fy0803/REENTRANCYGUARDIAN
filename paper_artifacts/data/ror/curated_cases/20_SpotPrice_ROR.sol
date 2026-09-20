// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISwapObserver20 {
    function onSwapQuoted20(address trader, uint256 amountOut) external;
}

contract RORSpotPriceBook20 {
    uint256 public reserveIn;
    uint256 public reserveOut;
    uint256 public stagedOut;

    function seed(uint256 inReserve, uint256 outReserve) external {
        reserveIn = inReserve;
        reserveOut = outReserve;
    }

    function spotPrice() external view returns (uint256) {
        return reserveIn * 1e18 / (reserveOut - stagedOut);
    }

    function stageOut(uint256 amountOut) external {
        stagedOut += amountOut;
    }

    function commitOut(uint256 amountOut) external {
        reserveOut -= amountOut;
        stagedOut -= amountOut;
    }
}

contract RORSpotPriceAMM20 {
    RORSpotPriceBook20 public immutable book;

    constructor(RORSpotPriceBook20 book_) {
        book = book_;
    }

    function spotPrice() external view returns (uint256) {
        return book.spotPrice();
    }

    function swapOut(uint256 amountOut, ISwapObserver20 observer) external {
        book.stageOut(amountOut);
        observer.onSwapQuoted20(msg.sender, amountOut);
        book.commitOut(amountOut);
    }
}

contract RORSpotPriceVault20 {
    RORSpotPriceAMM20 public immutable amm;
    mapping(address => uint256) public minted;

    constructor(RORSpotPriceAMM20 amm_) {
        amm = amm_;
    }

    function mintAgainstLP(uint256 lpAmount) external {
        minted[msg.sender] += lpAmount * amm.spotPrice() / 1e18;
    }
}
