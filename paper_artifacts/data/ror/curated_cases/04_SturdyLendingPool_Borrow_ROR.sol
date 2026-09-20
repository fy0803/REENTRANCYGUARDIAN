// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface IATokenLike {
    function transferUnderlyingTo(address user, uint256 amount) external returns (uint256);
}

/// @notice Reduced Sturdy/Aave-style LendingPool borrow sample for read-only reentrancy detection.
/// @dev This keeps the borrow order from the original LendingPool flow:
///      borrow() -> _executeBorrow() -> debt accounting/rate update -> transferUnderlyingTo().
///      During the external aToken transfer, read-only queries can observe a reserve state where
///      debt/rates were updated while available liquidity is not finalized yet.
contract LendingPool {
    struct ReserveData {
        uint256 liquidityIndex;
        uint256 variableBorrowIndex;
        uint256 currentLiquidityRate;
        uint256 currentVariableBorrowRate;
        uint256 availableLiquidity;
        uint256 totalVariableDebt;
        address aTokenAddress;
    }

    struct UserAccountData {
        uint256 collateral;
        uint256 debt;
        bool borrowing;
    }

    mapping(address => ReserveData) internal _reserves;
    mapping(address => UserAccountData) internal _users;

    event Borrow(
        address indexed reserve,
        address indexed user,
        address indexed onBehalfOf,
        uint256 amount,
        uint256 interestRateMode,
        uint256 borrowRate,
        uint16 referralCode
    );

    constructor(address asset, address aToken) {
        ReserveData storage reserve = _reserves[asset];
        reserve.liquidityIndex = 1e27;
        reserve.variableBorrowIndex = 1e27;
        reserve.currentLiquidityRate = 1e25;
        reserve.currentVariableBorrowRate = 2e25;
        reserve.availableLiquidity = 1_000 ether;
        reserve.aTokenAddress = aToken;
    }

    function borrow(
        address asset,
        uint256 amount,
        uint256 interestRateMode,
        uint16 referralCode,
        address onBehalfOf
    ) external {
        _executeBorrow(asset, msg.sender, onBehalfOf, amount, interestRateMode, referralCode, true);
    }

    function _executeBorrow(
        address asset,
        address user,
        address onBehalfOf,
        uint256 amount,
        uint256 interestRateMode,
        uint16 referralCode,
        bool releaseUnderlying
    ) internal {
        ReserveData storage reserve = _reserves[asset];
        UserAccountData storage account = _users[onBehalfOf];

        require(reserve.availableLiquidity >= amount, "NOT_ENOUGH_LIQUIDITY");

        _updateState(reserve);

        account.debt += amount;
        account.borrowing = true;
        reserve.totalVariableDebt += amount;

        _updateInterestRates(reserve, amount);

        if (releaseUnderlying) {
            IATokenLike(reserve.aTokenAddress).transferUnderlyingTo(user, amount);

            reserve.availableLiquidity -= amount;
        }

        emit Borrow(
            asset,
            user,
            onBehalfOf,
            amount,
            interestRateMode,
            reserve.currentVariableBorrowRate,
            referralCode
        );
    }

    function _updateState(ReserveData storage reserve) internal {
        reserve.liquidityIndex = reserve.liquidityIndex + reserve.currentLiquidityRate;
        reserve.variableBorrowIndex = reserve.variableBorrowIndex + reserve.currentVariableBorrowRate;
    }

    function _updateInterestRates(ReserveData storage reserve, uint256 liquidityTaken) internal {
        reserve.currentLiquidityRate = reserve.currentLiquidityRate + liquidityTaken / 100;
        reserve.currentVariableBorrowRate = reserve.currentVariableBorrowRate + liquidityTaken / 50;
    }

    function getUserAccountData(
        address user
    )
        external
        view
        returns (
            uint256 totalCollateralETH,
            uint256 totalDebtETH,
            uint256 availableBorrowsETH,
            uint256 currentLiquidationThreshold,
            uint256 ltv,
            uint256 healthFactor
        )
    {
        UserAccountData storage account = _users[user];
        totalCollateralETH = account.collateral;
        totalDebtETH = account.debt;
        availableBorrowsETH = account.collateral > account.debt ? account.collateral - account.debt : 0;
        currentLiquidationThreshold = 8_000;
        ltv = account.borrowing ? 7_500 : 0;
        healthFactor = account.debt == 0 ? type(uint256).max : account.collateral * 1e18 / account.debt;
    }

    function getReserveData(
        address asset
    )
        external
        view
        returns (
            uint256 liquidityIndex,
            uint256 variableBorrowIndex,
            uint256 currentLiquidityRate,
            uint256 currentVariableBorrowRate,
            uint256 availableLiquidity,
            uint256 totalVariableDebt
        )
    {
        ReserveData storage reserve = _reserves[asset];
        liquidityIndex = reserve.liquidityIndex;
        variableBorrowIndex = reserve.variableBorrowIndex;
        currentLiquidityRate = reserve.currentLiquidityRate;
        currentVariableBorrowRate = reserve.currentVariableBorrowRate;
        availableLiquidity = reserve.availableLiquidity;
        totalVariableDebt = reserve.totalVariableDebt;
    }

    function getReserveNormalizedIncome(address asset) external view returns (uint256) {
        return _reserves[asset].liquidityIndex;
    }

    function getReserveNormalizedVariableDebt(address asset) external view returns (uint256) {
        return _reserves[asset].variableBorrowIndex;
    }
}
