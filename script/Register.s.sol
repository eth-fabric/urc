// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/IRegistry.sol";
import "./BaseScript.s.sol";
import "../src/lib/BLS.sol";

contract RegisterScript is BaseScript {
    struct RegistrationJson {
        address owner;
        bytes signedRegistrations;
    }

    // forge script script/Register.s.sol:RegisterScript --sig "register(address,uint256,string)" $REGISTRY_ADDRESS $COLLATERAL $INFILE --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function register(address _registry, uint256 collateralWei, string memory signedRegistrationsFile) external {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Read user's pre-signed registrations
        (address owner, IRegistry.SignedRegistration[] memory registrations) =
            _readSignedRegistrations(signedRegistrationsFile);

        // Confirm with user
        string memory prompt = string(abi.encodePacked(vm.toString(owner), " is the correct owner? 1=yes, 0=no"));
        uint256 answer = vm.promptUint(prompt);
        if (answer != 1) revert("incorrect owner address");

        prompt = string(abi.encodePacked(vm.toString(collateralWei), " is the correct collateral? 1=yes, 0=no"));
        answer = vm.promptUint(prompt);
        if (answer != 1) revert("incorrect collateral amounts");

        prompt = string(abi.encodePacked(_buildPubkeyStrings(registrations), "are the correct pubkeys? 1=yes, 0=no"));
        answer = vm.promptUint(prompt);
        if (answer != 1) revert("incorrect pubkeys");

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call register
        bytes32 registrationRoot = registry.register{ value: collateralWei }(registrations, owner);

        console.log("Success! got registrationRoot:");
        console.logBytes32(registrationRoot);

        vm.stopBroadcast();
    }

    /// @dev NOT MEANT FOR PRODUCTION USE
    /// @dev Signs N registration messages and writes them to `outfile`
    /// @dev Derives N dummy BLS private keys from the `owner` address
    // forge script script/Register.s.sol:RegisterScript --sig "nDummyRegistrations(uint256,address,string)" $N $OWNER $OUTFILE
    function nDummyRegistrations(uint256 n, address owner, string memory outfile) public {
        console.log("Running nDummyRegistrations()... WARNING do not use the output in production!!!");

        // The n'th private key will = startPrivateKey + n
        uint256 startPrivateKey = uint256(keccak256(abi.encode(owner)));

        // Sign the registration messages
        IRegistry.SignedRegistration[] memory registrations = _nRegistrations(n, startPrivateKey, owner);

        // Write them to a JSON file
        _writeSignedRegistrations(owner, registrations, outfile);

        // Read them back to the User
        _readSignedRegistrations(outfile);
    }

    function _writeSignedRegistrations(
        address _owner,
        IRegistry.SignedRegistration[] memory _registrations,
        string memory _outfile
    ) public {
        // Write to json outfile if specified otherwise default "output/SignedRegistrations.json"
        (string memory _jsonFile,) = _getDefaultJson(_outfile, "SignedRegistrations.json");

        // Write the owner address to the json file
        vm.writeJson(vm.toString(_owner), _jsonFile, ".owner");

        // Encode the signed registrations as abi-encoded bytes
        vm.writeJson(vm.toString(abi.encode(_registrations)), _jsonFile, ".signedRegistrations");

        console.log("SignedRegistrations written to", _jsonFile);
    }

    function _readSignedRegistrations(string memory _infile)
        public
        returns (address owner, IRegistry.SignedRegistration[] memory registrations)
    {
        string memory jsonFile = string(abi.encodePacked("script/output/", _infile));
        string memory json = vm.readFile(jsonFile);
        bytes memory data = vm.parseJson(json);

        // Decode the RegistrationJson
        RegistrationJson memory registrationJson = abi.decode(data, (RegistrationJson));

        owner = registrationJson.owner;
        registrations = abi.decode(registrationJson.signedRegistrations, (IRegistry.SignedRegistration[]));

        console.log("Owner address:", registrationJson.owner);
        console.log("Total signed registrations:", registrations.length);
        console.log("Pubkeys:");
        console.log(_buildPubkeyStrings(registrations));
    }

    function _buildPubkeyStrings(IRegistry.SignedRegistration[] memory registrations)
        internal
        returns (string memory)
    {
        string memory s;
        for (uint256 i = 0; i < registrations.length; i++) {
            BLS.Fp memory compressed = BLS.compress(registrations[i].pubkey);
            bytes memory pubkey = abi.encode(compressed);
            bytes memory pubkeyPretty = new bytes(48);
            for (uint256 j = 16; j < pubkey.length; j++) {
                pubkeyPretty[j - 16] = pubkey[j];
            }
            s = string(abi.encodePacked(s, vm.toString(pubkeyPretty), ",\n"));
        }
        return s;
    }
}
