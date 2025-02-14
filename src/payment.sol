// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract PreconfPayment {
    // Modifiable price set by the gateway
    uint256 public price;

    // Contract wallet where funds are sent
    address public contractWallet;

    // Gateway address for contract management
    address public gateway;

    // User deposit structure
    struct Deposit {
        uint256 amount;
        uint256 withdrawalTime;
    }

    // Mapping of user deposits
    mapping(address => Deposit) public deposits;

    // Events
    event Deposited(address indexed user, uint256 amount);
    event PaymentRequested(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event PriceUpdated(uint256 newPrice);

    // Modifiers
    modifier onlyGateway() {
        require(msg.sender == gateway, "Only gateway can perform this action");
        _;
    }

    modifier hasDeposit(address user) {
        require(deposits[user].amount > 0, "No deposit found for user");
        _;
    }

    // Constructor
    constructor(address _gateway, address _contractWallet, uint256 _initialPrice) {
        require(_gateway != address(0), "Invalid gateway address");
        require(_contractWallet != address(0), "Invalid contract wallet address");
        require(_initialPrice > 0, "Price must be greater than zero");

        gateway = _gateway;
        contractWallet = _contractWallet;
        price = _initialPrice;
    }

    // Function to set the price (only by gateway)
    function setPrice(uint256 _newPrice) external onlyGateway {
        require(_newPrice > 0, "Price must be greater than zero");
        price = _newPrice;

        emit PriceUpdated(_newPrice);
    }

    // Function to deposit Ether into the contract
    function deposit() external payable {
       require(msg.value >= price, "Deposit amount must be at least the required price");

        // Update deposit balance and set withdrawal time (30 minutes from now)
        deposits[msg.sender].amount += msg.value;
        deposits[msg.sender].withdrawalTime = block.timestamp + 30 minutes;

        emit Deposited(msg.sender, msg.value);
    }

    // Function to request payment to the contract wallet
    function requestPayment(uint256 _amount) external hasDeposit(msg.sender) {
        require(_amount > 0, "Requested amount must be greater than zero");
        require(
            deposits[msg.sender].amount >= _amount,
            "Insufficient deposit amount"
        );

        // Deduct the amount from the user's deposit
        deposits[msg.sender].amount -= _amount;

        // Transfer the requested amount to the contract wallet
        (bool success, ) = contractWallet.call{value: _amount}("");
        require(success, "Payment transfer failed");

        emit PaymentRequested(msg.sender, _amount);
    }

    // Function to withdraw deposited funds (after 30-minute lock period)
    function withdraw() external hasDeposit(msg.sender) {
        require(
            block.timestamp >= deposits[msg.sender].withdrawalTime,
            "Withdrawal time has not yet passed"
        );

        uint256 amount = deposits[msg.sender].amount;

        // Reset user deposit
        deposits[msg.sender].amount = 0;
        deposits[msg.sender].withdrawalTime = 0;

        // Transfer the funds back to the user
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdrawal transfer failed");

        emit Withdrawn(msg.sender, amount);
    }

    // Fallback function to prevent accidental Ether transfers
    receive() external payable {
        revert("Direct Ether transfers are not allowed");
    }

    fallback() external payable {
        revert("Function does not exist");
    }
}
