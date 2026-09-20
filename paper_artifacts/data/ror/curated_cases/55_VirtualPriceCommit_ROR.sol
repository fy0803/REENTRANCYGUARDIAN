// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurveSettlement55 {
    function settleRemove55(address account, uint256 lpAmount, uint256 virtualPrice) external;
}

contract VirtualPriceCommit55 {
    struct RemovalQuote {
        uint256 lpAmount;
        uint256 virtualPrice;
        uint256 timestamp;
    }

    mapping(address => uint256) public lpBalance;
    mapping(address => RemovalQuote) public quotes;
    uint256 public totalSupply = 1_000 ether;
    uint256 public balanceA = 1_000 ether;
    uint256 public balanceB = 1_000 ether;
    uint256 public adminFeeBps = 4;
    uint256 public virtualPriceCache = 2e18;

    event RemovalCommitted(address indexed account, uint256 lpAmount, uint256 virtualPrice);

    function seed(address user, uint256 lp, uint256 a, uint256 b) external {
        lpBalance[user] = lp;
        totalSupply = lp;
        balanceA = a;
        balanceB = b;
        virtualPriceCache = (a + b) * 1e18 / lp;
    }

    function get_virtual_price() external view returns (uint256) {
        return virtualPriceCache;
    }

    function quoteRemove(uint256 lpAmount) external view returns (uint256, uint256) {
        uint256 gross = lpAmount * virtualPriceCache / 1e18;
        uint256 fee = gross * adminFeeBps / 10_000;
        return (gross - fee, fee);
    }

    function commitRemoveLiquidity(uint256 lpAmount, address settlement) external {
        require(lpAmount > 0 && lpAmount <= lpBalance[msg.sender], "BAD_LP");

        lpBalance[msg.sender] -= lpAmount;
        totalSupply -= lpAmount;
        virtualPriceCache = (balanceA + balanceB) * 1e18 / totalSupply;
        quotes[msg.sender] = RemovalQuote(lpAmount, virtualPriceCache, block.timestamp);

        emit RemovalCommitted(msg.sender, lpAmount, virtualPriceCache);
        ICurveSettlement55(settlement).settleRemove55(msg.sender, lpAmount, virtualPriceCache);
    }
}

