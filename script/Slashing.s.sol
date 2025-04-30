// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/IRegistry.sol";
import "./BaseScript.s.sol";
import "../src/lib/BLS.sol";

contract SlashingScript is BaseScript {
    // forge script script/Slashing.s.sol:SlashingScript --sig "registerBadRegistration(address,address,string)" $REGISTRY_ADDRESS $OWNER $SIGNED_REGISTRATIONS_FILE --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function registerBadRegistration(address _registry, address owner, string memory outfile)
        external
        returns (bytes32 registrationRoot)
    {
        // Generate an invalid BLS registration using a deterministic private key
        uint256 privateKey = 12345;
        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](1);
        // don't sign over the owner address
        registrations[0] = _signTestRegistration(privateKey, address(1337));

        // Write the invalid registration to file
        _writeSignedRegistrations(owner, registrations, outfile);

        // Log the bad compressed pubkey
        console.log("Bad pubkey:", vm.toString(_prettyPubKey(abi.encode(BLS.compress(registrations[0].pubkey)))));

        // Start broadcasting transactions
        vm.startBroadcast();

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Use the minimum collateral amount
        uint256 collateralWei = registry.getConfig().minCollateralWei;

        // Register the invalid registration
        registrationRoot = registry.register{ value: collateralWei }(registrations, owner);

        console.log("Registered bad registration with root:", vm.toString(registrationRoot));

        vm.stopBroadcast();
    }

    // forge script script/Slashing.s.sol:SlashingScript --sig "slashRegistration(address,string)" $REGISTRY_ADDRESS $REGISTRATION_PROOF_FILE --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function slashRegistration(address _registry, string memory registrationProofFile) external {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Read the registration proof from file
        IRegistry.RegistrationProof memory proof = _readRegistrationProof(registrationProofFile);

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call slashRegistration
        uint256 slashedCollateralWei = registry.slashRegistration(proof);

        console.log("Slashed collateral:", slashedCollateralWei);

        vm.stopBroadcast();
    }
}
