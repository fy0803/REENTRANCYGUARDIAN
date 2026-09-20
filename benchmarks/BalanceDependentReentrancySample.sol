// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BalanceDependentReentrancySample {
    function sendCall(address payable refundTo, address payable target, bytes calldata callData)
        external
        payable
    {
        (bool success, ) = target.call{value: msg.value}(callData);
        require(success, "call failed");

        uint256 ethBalance = address(this).balance;
        if (ethBalance != 0) {
            (success, ) = refundTo.call{value: ethBalance}("");
            require(success, "refund failed");
        }
    }

    receive() external payable {}
}
