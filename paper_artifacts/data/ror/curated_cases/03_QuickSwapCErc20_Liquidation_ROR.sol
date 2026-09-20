// SPDX-License-Identifier: MIT
pragma solidity ^0.5.16;

interface EIP20Interface {
    function transferFrom(address src, address dst, uint256 amount) external returns (bool);
}

interface CTokenInterface {
    function seize(address liquidator, address borrower, uint256 seizeTokens) external returns (uint256);
}

/// @notice Reduced QuickSwap/Compound CErc20 liquidation sample for read-only reentrancy detection.
/// @dev This keeps the liquidation accounting order from the original CToken flow:
///      liquidateBorrow() -> liquidateBorrowFresh() -> repayBorrowFresh() -> doTransferIn().
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
    uint256 public totalBorrows = 50 ether;
    uint256 public totalReserves;
    uint256 public totalSupply = 100 ether;
    uint256 public cash = 100 ether;

    event RepayBorrow(
        address payer,
        address borrower,
        uint256 repayAmount,
        uint256 accountBorrows,
        uint256 totalBorrows
    );

    event LiquidateBorrow(
        address liquidator,
        address borrower,
        uint256 repayAmount,
        address cTokenCollateral,
        uint256 seizeTokens
    );

    constructor(address underlying_) public {
        underlying = underlying_;
        accrualBlockNumber = block.number;
    }

    function liquidateBorrow(
        address borrower,
        uint256 repayAmount,
        CTokenInterface cTokenCollateral
    ) external returns (uint256) {
        return liquidateBorrowInternal(borrower, repayAmount, cTokenCollateral);
    }

    function liquidateBorrowInternal(
        address borrower,
        uint256 repayAmount,
        CTokenInterface cTokenCollateral
    ) internal returns (uint256) {
        accrueInterest();
        return liquidateBorrowFresh(msg.sender, borrower, repayAmount, cTokenCollateral);
    }

    function liquidateBorrowFresh(
        address liquidator,
        address borrower,
        uint256 repayAmount,
        CTokenInterface cTokenCollateral
    ) internal returns (uint256) {
        require(borrower != liquidator, "LIQUIDATE_LIQUIDATOR_IS_BORROWER");

        uint256 actualRepayAmount = repayBorrowFresh(liquidator, borrower, repayAmount);
        uint256 seizeTokens = actualRepayAmount * 2;

        require(
            cTokenCollateral.seize(liquidator, borrower, seizeTokens) == 0,
            "LIQUIDATE_SEIZE_FAILED"
        );

        emit LiquidateBorrow(
            liquidator,
            borrower,
            actualRepayAmount,
            address(cTokenCollateral),
            seizeTokens
        );
        return 0;
    }

    function repayBorrowFresh(
        address payer,
        address borrower,
        uint256 repayAmount
    ) internal returns (uint256) {
        uint256 accountBorrowsPrev = borrowBalanceStoredInternal(borrower);
        uint256 repayAmountFinal = repayAmount;
        if (repayAmountFinal > accountBorrowsPrev) {
            repayAmountFinal = accountBorrowsPrev;
        }

        uint256 actualRepayAmount = doTransferIn(payer, repayAmountFinal);
        uint256 accountBorrowsNew = accountBorrowsPrev - actualRepayAmount;
        uint256 totalBorrowsNew = totalBorrows - actualRepayAmount;

        accountBorrows[borrower].principal = accountBorrowsNew;
        accountBorrows[borrower].interestIndex = borrowIndex;
        totalBorrows = totalBorrowsNew;

        emit RepayBorrow(
            payer,
            borrower,
            actualRepayAmount,
            accountBorrowsNew,
            totalBorrowsNew
        );
        return actualRepayAmount;
    }

    function accrueInterest() internal {
        accrualBlockNumber = block.number;
    }

    function doTransferIn(address from, uint256 amount) internal returns (uint256) {
        require(
            EIP20Interface(underlying).transferFrom(from, address(this), amount),
            "TOKEN_TRANSFER_IN_FAILED"
        );

        cash = cash + amount;
        return amount;
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
        BorrowSnapshot storage borrowSnapshot = accountBorrows[account];
        if (borrowSnapshot.principal == 0) {
            return 0;
        }
        return borrowSnapshot.principal * borrowIndex / borrowSnapshot.interestIndex;
    }
}
