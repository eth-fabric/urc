// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/IRegistry.sol";
import "./BaseScript.s.sol";

contract GettersScript is BaseScript {
    // forge script script/Getters.s.sol:GettersScript --sig "getConfig(address,string)" $REGISTRY_ADDRESS $CONFIG_FILE --rpc-url $RPC_URL
    function getConfig(address _registry, string memory outfile) public returns (IRegistry.Config memory config) {
        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Get the config
        config = registry.getConfig();

        // Log the config
        console.log("Min collateral:", config.minCollateralWei);
        console.log("Fraud proof window:", config.fraudProofWindow);
        console.log("Unregistration delay:", config.unregistrationDelay);
        console.log("Slash window:", config.slashWindow);
        console.log("Opt-in delay:", config.optInDelay);

        // Write to json outfile if specified otherwise default "output/getConfig.json"
        (string memory jsonFile,) = _getDefaultJson(outfile, "getConfig.json");
        vm.writeJson(vm.toString(config.minCollateralWei), jsonFile, ".minCollateralWei");
        vm.writeJson(vm.toString(config.fraudProofWindow), jsonFile, ".fraudProofWindow");
        vm.writeJson(vm.toString(config.unregistrationDelay), jsonFile, ".unregistrationDelay");
        vm.writeJson(vm.toString(config.slashWindow), jsonFile, ".slashWindow");
        vm.writeJson(vm.toString(config.optInDelay), jsonFile, ".optInDelay");

        console.log("Config written to", jsonFile);
    }

    // forge script script/Getters.s.sol:GettersScript --sig "getOperatorData(address,bytes32,string)" $REGISTRY_ADDRESS $REGISTRATION_ROOT $OPERATOR_DATA_FILE --rpc-url $RPC_URL
    function getOperatorData(address _registry, bytes32 _registrationRoot, string memory outfile)
        public
        returns (IRegistry.OperatorData memory operatorData)
    {
        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Get the operator data
        operatorData = registry.getOperatorData(_registrationRoot);

        console.log("Owner:", operatorData.owner);
        console.log("Collateral Wei:", operatorData.collateralWei);
        console.log("Num keys:", operatorData.numKeys);
        console.log("Registered at:", operatorData.registeredAt);
        console.log("Unregistered at:", operatorData.unregisteredAt);
        console.log("Slashed at:", operatorData.slashedAt);
        console.log("Deleted:", operatorData.deleted);
        console.log("Equivocated:", operatorData.equivocated);

        // Write to json outfile if specified otherwise default "output/getOperatorData.json"
        (string memory jsonFile,) = _getDefaultJson(outfile, "getOperatorData.json");
        vm.writeJson(vm.toString(operatorData.owner), jsonFile, ".owner");
        vm.writeJson(vm.toString(operatorData.collateralWei), jsonFile, ".collateralWei");
        vm.writeJson(vm.toString(operatorData.numKeys), jsonFile, ".numKeys");
        vm.writeJson(vm.toString(operatorData.registeredAt), jsonFile, ".registeredAt");
        vm.writeJson(vm.toString(operatorData.unregisteredAt), jsonFile, ".unregisteredAt");
        vm.writeJson(vm.toString(operatorData.slashedAt), jsonFile, ".slashedAt");
        vm.writeJson(vm.toString(operatorData.deleted), jsonFile, ".deleted");

        console.log("OperatorData written to", jsonFile);
    }

    // forge script script/Getters.s.sol:GettersScript --sig "getSlasherCommitment(address,bytes32,address,string)" $REGISTRY_ADDRESS $REGISTRATION_ROOT $SLASHER $SLASHER_COMMITMENT_FILE --rpc-url $RPC_URL
    function getSlasherCommitment(address _registry, bytes32 _registrationRoot, address _slasher, string memory outfile)
        public
        returns (IRegistry.SlasherCommitment memory slasherCommitment)
    {
        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Get the slasher commitment
        slasherCommitment = registry.getSlasherCommitment(_registrationRoot, _slasher);

        console.log("Committer:", slasherCommitment.committer);
        console.log("Opted in at:", slasherCommitment.optedInAt);
        console.log("Opted out at:", slasherCommitment.optedOutAt);
        console.log("Slashed:", slasherCommitment.slashed);

        // Write to json outfile if specified otherwise default "output/SlasherCommitment.json"
        (string memory jsonFile,) = _getDefaultJson(outfile, "SlasherCommitment.json");
        vm.writeJson(vm.toString(slasherCommitment.committer), jsonFile, ".committer");
        vm.writeJson(vm.toString(slasherCommitment.optedInAt), jsonFile, ".optedInAt");
        vm.writeJson(vm.toString(slasherCommitment.optedOutAt), jsonFile, ".optedOutAt");
        vm.writeJson(vm.toString(slasherCommitment.slashed), jsonFile, ".slashed");

        console.log("SlasherCommitment written to", jsonFile);
    }

    // forge script script/Getters.s.sol:GettersScript --sig "getRegistrationProof(address,bytes,string,string)" $REGISTRY_ADDRESS $PUBKEY $SIGNED_REGISTRATIONS_FILE $REGISTRATION_PROOF_FILE --account $FOUNDRY_WALLET --rpc-url $RPC_URL
    function getRegistrationProof(
        address _registry,
        bytes memory pubkey,
        string memory signedRegistrationsFile,
        string memory outfile
    ) public returns (IRegistry.RegistrationProof memory proof) {
        require(pubkey.length == 48, "invalid pubkey length");

        // Read user's pre-signed registrations
        (address owner, IRegistry.SignedRegistration[] memory registrations) =
            _readSignedRegistrations(signedRegistrationsFile);

        // Find the leafindex from the pubkey
        uint256 leafIndex = type(uint256).max;
        bytes32 hashedPubKey = keccak256(pubkey);
        for (uint256 i = 0; i < registrations.length; i++) {
            bytes memory compressed = abi.encode(BLS.compress(registrations[i].pubkey));
            bytes memory pubkeyPretty = _prettyPubKey(compressed);
            if (hashedPubKey == keccak256(pubkeyPretty)) {
                leafIndex = i;
                break;
            }
        }

        console.log("Pubkey matches at leafIndex:", leafIndex);

        if (leafIndex == type(uint256).max) revert("pubkey not found in file");

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call getRegistrationProof
        proof = registry.getRegistrationProof(registrations, owner, leafIndex);

        bytes32 writeProofHash = keccak256(abi.encode(proof));
        _writeRegistrationProof(proof, outfile);

        bytes32 readProofHash = keccak256(abi.encode(_readRegistrationProof(outfile)));

        require(writeProofHash == readProofHash, "Something went wrong!");
    }
}
