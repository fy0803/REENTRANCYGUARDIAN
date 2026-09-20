// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IReserveSettlement57 {
    function settleDebt57(address borrower, uint256 amount, uint256 index) external;
}

contract ReserveIndexCommit57 {
    struct ReserveSnapshot {
        uint256 liquidity;
        uint256 debt;
        uint256 index;
        uint256 lastUpdate;
    }

    ReserveSnapshot public reserve = ReserveSnapshot({
        liquidity: 1_000 ether,
        debt: 0,
        index: 1e27,
        lastUpdate: 0
    });
    mapping(address => uint256) public principalDebt;
    uint256 public reserveFactorBps = 1_000;
    uint256 public utilizationCache;

    event DebtIssued(address indexed borrower, uint256 amount, uint256 index);

    function getReserveNormalizedIncome() external view returns (uint256) {
        return reserve.index;
    }

    function utilization() external view returns (uint256) {
        return utilizationCache;
    }

    function issueDebt(uint256 amount, address settlement) external {
        require(amount > 0 && amount < reserve.liquidity, "BAD_AMOUNT");

        principalDebt[msg.sender] += amount;
        reserve.debt += amount;
        reserve.index = reserve.index + amount * 1e9;
        reserve.lastUpdate = block.timestamp;
        utilizationCache = reserve.debt * 1e18 / reserve.liquidity;

        emit DebtIssued(msg.sender, amount, reserve.index);
        IReserveSettlement57(settlement).settleDebt57(msg.sender, amount, reserve.index);
    }
}

