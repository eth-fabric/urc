// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/IRegistry.sol";
import "./BaseScript.s.sol";

contract CollateralScript is BaseScript {
    // forge script script/Collateral.s.sol:CollateralScript --sig "addCollateral(address,bytes32,uint256)" $REGISTRY_ADDRESS $REGISTRATION_ROOT $COLLATERAL --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function addCollateral(address _registry, bytes32 registrationRoot, uint256 collateralWei) external {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Confirm with user
        string memory prompt =
            string(abi.encodePacked(vm.toString(collateralWei), " wei is the correct collateral? 1=yes, 0=no"));
        uint256 answer = vm.promptUint(prompt);
        if (answer != 1) revert("incorrect collateral amounts");

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call addCollateral
        registry.addCollateral{ value: collateralWei }(registrationRoot);

        vm.stopBroadcast();
    }

    // forge script script/Collateral.s.sol:CollateralScript --sig "claimCollateral(address,bytes32)" $REGISTRY_ADDRESS $REGISTRATION_ROOT --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function claimCollateral(address _registry, bytes32 registrationRoot) external {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call claimCollateral
        registry.claimCollateral(registrationRoot);

        vm.stopBroadcast();
    }

    // forge script script/Collateral.s.sol:CollateralScript --sig "claimSlashedCollateral(address,bytes32)" $REGISTRY_ADDRESS $REGISTRATION_ROOT --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function claimSlashedCollateral(address _registry, bytes32 registrationRoot) external {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call claimSlashedCollateral
        registry.claimSlashedCollateral(registrationRoot);

        vm.stopBroadcast();
    }
}
