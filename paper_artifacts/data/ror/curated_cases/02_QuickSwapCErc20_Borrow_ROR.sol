// SPDX-License-Identifier: MIT
pragma solidity ^0.5.16;

interface EIP20Interface {
    function balanceOf(address owner) external view returns (uint256);
    function transfer(address dst, uint256 amount) external returns (bool);
}

/// @notice Reduced QuickSwap/Compound CErc20 borrow sample for read-only reentrancy detection.
/// @dev This keeps the borrow accounting order from the original CToken flow:
///      borrow() -> borrowInternal() -> borrowFresh() -> doTransferOut().
///      During the external token transfer, exchangeRateStored() can observe stale cash.
contract CErc20 {
    struct BorrowSnapshot {
        uint256 principal;
        uint256 interestIndex;
    }

    address public underlying;
    mapping(address => BorrowSnapshot) public accountBorrows;

    uint256 public accrualBlockNumber;
    uint256 public borrowIndex = 1e18;
    uint256 public totalBorrows;
    uint256 public totalReserves;
    uint256 public totalSupply = 100 ether;
    uint256 public cash = 100 ether;

    event Borrow(
        address borrower,
        uint256 borrowAmount,
        uint256 accountBorrows,
        uint256 totalBorrows
    );

    constructor(address underlying_) public {
        underlying = underlying_;
        accrualBlockNumber = block.number;
    }

    function borrow(uint256 borrowAmount) external returns (uint256) {
        return borrowInternal(borrowAmount);
    }

    function borrowInternal(uint256 borrowAmount) internal returns (uint256) {
        accrueInterest();
        return borrowFresh(msg.sender, borrowAmount);
    }

    function borrowFresh(address payable borrower, uint256 borrowAmount) internal returns (uint256) {
        require(getCashPrior() >= borrowAmount, "TOKEN_INSUFFICIENT_CASH");

        uint256 accountBorrowsPrev = borrowBalanceStoredInternal(borrower);
        uint256 accountBorrowsNew = accountBorrowsPrev + borrowAmount;
        uint256 totalBorrowsNew = totalBorrows + borrowAmount;

        accountBorrows[borrower].principal = accountBorrowsNew;
        accountBorrows[borrower].interestIndex = borrowIndex;
        totalBorrows = totalBorrowsNew;

        doTransferOut(borrower, borrowAmount);

        emit Borrow(borrower, borrowAmount, accountBorrowsNew, totalBorrowsNew);
        return 0;
    }

    function accrueInterest() internal {
        accrualBlockNumber = block.number;
    }

    function getCashPrior() internal view returns (uint256) {
        return cash;
    }

    function doTransferOut(address payable to, uint256 amount) internal {
        require(EIP20Interface(underlying).transfer(to, amount), "TOKEN_TRANSFER_OUT_FAILED");

        cash = cash - amount;
    }

    function exchangeRateStored() public view returns (uint256) {
        if (totalSupply == 0) {
            return 2e26;
        }

        uint256 cashPlusBorrowsMinusReserves = cash + totalBorrows - totalReserves;
        return cashPlusBorrowsMinusReserves * 1e18 / totalSupply;
    }

    function exchangeRateStoredInternal() internal view returns (uint256) {
        return exchangeRateStored();
    }

    function borrowBalanceStored(address account) external view returns (uint256) {
        return borrowBalanceStoredInternal(account);
    }

    function borrowBalanceStoredInternal(address account) internal view returns (uint256) {
        BorrowSnapshot storage borrowSnapshot = accountBorrows[account];
        if (borrowSnapshot.principal == 0) {
            return 0;
        }
        return borrowSnapshot.principal * borrowIndex / borrowSnapshot.interestIndex;
    }
}
