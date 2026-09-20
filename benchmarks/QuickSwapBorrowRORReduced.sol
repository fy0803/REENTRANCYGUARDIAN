pragma solidity ^0.8.0;

interface IReceiver {
    function onBorrow() external;
}

contract QuickSwapBorrowRORReduced {
    struct BorrowSnapshot {
        uint256 principal;
        uint256 interestIndex;
    }

    mapping(address => BorrowSnapshot) public accountBorrows;
    uint256 public borrowIndex = 1e18;
    uint256 public totalBorrows;
    uint256 public totalReserves;
    uint256 public totalSupply = 100 ether;
    uint256 public cash = 100 ether;

    function borrow(uint256 borrowAmount) external {
        borrowFresh(msg.sender, borrowAmount);
    }

    function borrowFresh(address borrower, uint256 borrowAmount) internal {
        uint256 accountBorrowsNew = accountBorrows[borrower].principal + borrowAmount;
        uint256 totalBorrowsNew = totalBorrows + borrowAmount;

        accountBorrows[borrower].principal = accountBorrowsNew;
        accountBorrows[borrower].interestIndex = borrowIndex;
        totalBorrows = totalBorrowsNew;

        doTransferOut(borrower, borrowAmount);
    }

    function doTransferOut(address borrower, uint256 amount) internal {
        IReceiver(borrower).onBorrow();
        cash -= amount;
    }

    function exchangeRateStored() public view returns (uint256) {
        return (cash + totalBorrows - totalReserves) * 1e18 / totalSupply;
    }

    function borrowBalanceStored(address account) public view returns (uint256) {
        BorrowSnapshot storage snapshot = accountBorrows[account];
        return snapshot.principal * borrowIndex / snapshot.interestIndex;
    }
}
