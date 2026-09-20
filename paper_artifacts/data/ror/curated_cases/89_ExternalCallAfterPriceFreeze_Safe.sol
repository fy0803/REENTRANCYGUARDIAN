// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Settlement89 {
    function settle() external;
}

contract ExternalCallAfterPriceFreezeSafe89 {
    uint256 public frozenPrice;
    bool public priceFrozen;
    Settlement89 public settlement;

    constructor(Settlement89 settlement_) {
        settlement = settlement_;
    }

    function execute(uint256 price) external {
        frozenPrice = price;
        priceFrozen = true;
        settlement.settle();
    }

    function quote() external view returns (uint256) {
        require(priceFrozen, "not frozen");
        return frozenPrice;
    }
}
