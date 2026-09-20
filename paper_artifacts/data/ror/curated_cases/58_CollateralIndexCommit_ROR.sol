// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICollateralSettlement58 {
    function settleExit58(address account, uint256 shares, uint256 index) external;
}

contract CollateralIndexCommit58 {
    struct Account {
        uint256 shares;
        uint256 queuedShares;
    }

    mapping(address => Account) public accounts;
    uint256 public totalCollateral = 1_000 ether;
    uint256 public totalShares = 1_000 ether;
    uint256 public collateralIndexCache = 1e18;
    uint256 public exitNonce;
    uint256 public minimumShares = 1 ether;

    event ExitCommitted(address indexed account, uint256 shares, uint256 index);

    function seed(address user, uint256 shares, uint256 collateralAmount) external {
        accounts[user].shares = shares;
        totalShares = shares;
        totalCollateral = collateralAmount;
        collateralIndexCache = collateralAmount * 1e18 / shares;
    }

    function collateralIndex() external view returns (uint256) {
        return collateralIndexCache;
    }

    function accountValue(address user) external view returns (uint256) {
        return accounts[user].shares * collateralIndexCache / 1e18;
    }

    function exit(uint256 shares, address settlement) external {
        Account storage account = accounts[msg.sender];
        require(shares >= minimumShares && shares <= account.shares, "BAD_SHARES");

        account.shares -= shares;
        account.queuedShares += shares;
        totalShares -= shares;
        exitNonce += 1;
        collateralIndexCache = totalCollateral * 1e18 / totalShares;

        emit ExitCommitted(msg.sender, shares, collateralIndexCache);
        ICollateralSettlement58(settlement).settleExit58(msg.sender, shares, collateralIndexCache);
    }
}

