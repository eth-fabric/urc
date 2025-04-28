// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/Registry.sol";

contract DeployScript is Script {
    // forge script script/Deploy.s.sol:DeployScript --sig "deploy()" --rpc-url $RPC_URL --account $FOUNDRY_WALLET --broadcast 
    function deploy() external {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Read config from JSON file
        string memory configPath = "config/registry.json";
        string memory configJson = vm.readFile(configPath);
        
        IRegistry.Config memory config = IRegistry.Config({
            minCollateralWei: uint80(vm.parseJsonUint(configJson, ".minCollateralWei")),
            fraudProofWindow: uint32(vm.parseJsonUint(configJson, ".fraudProofWindow")),
            unregistrationDelay: uint32(vm.parseJsonUint(configJson, ".unregistrationDelay")),
            slashWindow: uint32(vm.parseJsonUint(configJson, ".slashWindow")),
            optInDelay: uint32(vm.parseJsonUint(configJson, ".optInDelay"))
        });

        // Deploy the Registry contract
        Registry registry = new Registry(config);

        // Log the deployed address
        console.log("Registry deployed to:", address(registry));

        vm.stopBroadcast();
    }
}
