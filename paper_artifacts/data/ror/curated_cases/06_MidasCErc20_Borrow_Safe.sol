// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface EIP20Interface {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @notice Reduced Midas/Compound-style CErc20Delegator borrow negative sample.
/// @dev The original dataset entry was only a delegator shell with missing imports.
///      This self-contained version keeps a borrow flow but finalizes accounting
///      before the external token transfer, so read-only callbacks observe a
///      consistent reserve state.
contract CErc20Delegator {
    struct BorrowSnapshot {
        uint256 principal;
        uint256 interestIndex;
    }

    address public immutable underlying;

    mapping(address => BorrowSnapshot) public accountBorrows;
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

    constructor(address underlying_) {
        underlying = underlying_;
    }

    function borrow(uint256 borrowAmount) external returns (uint256) {
        return borrowInternal(borrowAmount);
    }

    function borrowInternal(uint256 borrowAmount) internal returns (uint256) {
        accrueInterest();
        return borrowFresh(msg.sender, borrowAmount);
    }

    function borrowFresh(address borrower, uint256 borrowAmount) internal returns (uint256) {
        require(cash >= borrowAmount, "TOKEN_INSUFFICIENT_CASH");

        uint256 accountBorrowsNew = borrowBalanceStoredInternal(borrower) + borrowAmount;
        uint256 totalBorrowsNew = totalBorrows + borrowAmount;
        uint256 cashNew = cash - borrowAmount;

        accountBorrows[borrower].principal = accountBorrowsNew;
        accountBorrows[borrower].interestIndex = borrowIndex;
        totalBorrows = totalBorrowsNew;
        cash = cashNew;

        doTransferOut(borrower, borrowAmount);

        emit Borrow(borrower, borrowAmount, accountBorrowsNew, totalBorrowsNew);
        return 0;
    }

    function accrueInterest() internal {
        borrowIndex = borrowIndex + 1;
    }

    function doTransferOut(address to, uint256 amount) internal {
        require(EIP20Interface(underlying).transfer(to, amount), "TOKEN_TRANSFER_OUT_FAILED");
    }

    function exchangeRateStored() public view returns (uint256) {
        if (totalSupply == 0) {
            return 2e26;
        }

        uint256 cashPlusBorrowsMinusReserves = cash + totalBorrows - totalReserves;
        return cashPlusBorrowsMinusReserves * 1e18 / totalSupply;
    }

    function borrowBalanceStored(address account) external view returns (uint256) {
        return borrowBalanceStoredInternal(account);
    }

    function borrowBalanceStoredInternal(address account) internal view returns (uint256) {
        BorrowSnapshot storage snapshot = accountBorrows[account];
        if (snapshot.principal == 0) {
            return 0;
        }
        return snapshot.principal * borrowIndex / snapshot.interestIndex;
    }
}
