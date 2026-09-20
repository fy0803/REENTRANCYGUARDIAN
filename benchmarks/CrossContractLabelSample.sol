// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RelayBridge {
    mapping(address => uint256) public balances;

    function forward(address user, uint256 amount) external {
        balances[user] += amount;
    }
}

contract CrossContractVault {
    mapping(address => uint256) public balances;
    RelayBridge public bridge;

    constructor(RelayBridge _bridge) {
        bridge = _bridge;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        bridge.forward(msg.sender, amount);
        balances[msg.sender] = 0;
    }
}
