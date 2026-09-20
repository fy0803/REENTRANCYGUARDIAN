// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDebtShareSettlement60 {
    function settleMint60(address account, uint256 shares, uint256 index) external;
}

contract DebtShareCommit60 {
    struct Borrower {
        uint256 debt;
        uint256 shares;
        uint256 lastIndex;
    }

    mapping(address => Borrower) public borrowers;
    uint256 public totalDebt = 1_000 ether;
    uint256 public totalDebtShares = 1_000 ether;
    uint256 public debtSharePrice = 1e18;
    uint256 public originationFeeBps = 50;
    uint256 public mintNonce;

    event DebtSharesMinted(address indexed account, uint256 shares, uint256 index);

    function debtIndex() external view returns (uint256) {
        return debtSharePrice;
    }

    function previewDebtShares(uint256 debtAmount) external view returns (uint256) {
        return debtAmount * 1e18 / debtSharePrice;
    }

    function mintDebtShares(uint256 debtAmount, address settlement) external {
        require(debtAmount > 0, "ZERO_DEBT");
        uint256 fee = debtAmount * originationFeeBps / 10_000;
        uint256 debtWithFee = debtAmount + fee;
        uint256 newShares = debtWithFee * 1e18 / debtSharePrice;

        borrowers[msg.sender].debt += debtWithFee;
        borrowers[msg.sender].shares += newShares;
        borrowers[msg.sender].lastIndex = debtSharePrice;
        totalDebt += debtWithFee;
        totalDebtShares += newShares;
        debtSharePrice = totalDebt * 1e18 / totalDebtShares;
        mintNonce += 1;

        emit DebtSharesMinted(msg.sender, newShares, debtSharePrice);
        IDebtShareSettlement60(settlement).settleMint60(msg.sender, newShares, debtSharePrice);
    }
}

