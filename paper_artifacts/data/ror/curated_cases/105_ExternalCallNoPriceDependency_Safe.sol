// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Messenger105 {
    function sendMessage(bytes calldata data) external;
}

contract ExternalCallNoPriceDependencySafe105 {
    uint256 public price = 1e18;
    Messenger105 public messenger;

    constructor(Messenger105 messenger_) {
        messenger = messenger_;
    }

    function notify(bytes calldata data) external {
        messenger.sendMessage(data);
    }

    function getPrice() external view returns (uint256) {
        return price;
    }
}
