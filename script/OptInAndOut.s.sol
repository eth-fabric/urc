// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/IRegistry.sol";
import "./BaseScript.s.sol";
import "../src/lib/BLS.sol";

contract OptInAndOutScript is BaseScript {
    // forge script script/OptInAndOut.s.sol:OptInAndOutScript --sig "optInToSlasher(address,bytes32,address,address)" $REGISTRY_ADDRESS $REGISTRATION_ROOT $SLASHER $COMMITTER --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function optInToSlasher(address _registry, bytes32 registrationRoot, address slasher, address committer) external {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Confirm with user
        string memory prompt = string(
            abi.encodePacked("Are you sure you want to opt in to slasher: ", vm.toString(slasher), "? 1=yes, 0=no")
        );
        uint256 answer = vm.promptUint(prompt);
        if (answer != 1) revert("incorrect slasher");

        prompt = string(
            abi.encodePacked(
                "Are you sure you want to use this committer address: ", vm.toString(committer), "? 1=yes, 0=no"
            )
        );
        answer = vm.promptUint(prompt);
        if (answer != 1) revert("incorrect committer");

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call optInToSlasher
        registry.optInToSlasher(registrationRoot, slasher, committer);

        vm.stopBroadcast();
    }
}
