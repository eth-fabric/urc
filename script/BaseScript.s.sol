// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/IRegistry.sol";
import "../src/lib/MerkleTree.sol";
import "../src/lib/BLS.sol";

contract BaseScript is Script {
    bytes public constant REGISTRATION_DOMAIN_SEPARATOR = "0x00555243"; // "URC" in little endian

    struct RegistrationJson {
        address owner;
        bytes signedRegistrations;
    }

    struct RegistrationProofJson {
        uint256 leafIndex;
        bytes merkleProof;
        bytes registration;
        bytes32 registrationRoot;
    }

    function _getDefaultJson(string memory _outfile, string memory _default)
        internal
        returns (string memory jsonFile, string memory jsonObj)
    {
        // Get the file path for the output json
        if (bytes(_outfile).length > 0) {
            jsonFile = string(abi.encodePacked("script/output/", _outfile));
        } else {
            jsonFile = string(abi.encodePacked("script/output/", _default));
        }

        // Read the default json object
        jsonObj = vm.readFile(string(abi.encodePacked("script/output/", _default)));

        // Copy the default json object to the new file to create the file if it doesn't exist
        vm.writeFile(jsonFile, jsonObj);

        return (jsonFile, jsonObj);
    }

    /// @dev NOT MEANT FOR PRODUCTION USE
    function _signTestRegistration(uint256 privateKey, address _owner)
        internal
        view
        returns (IRegistry.SignedRegistration memory signedRegistration)
    {
        BLS.G1Point memory pubkey = BLS.toPublicKey(privateKey);
        bytes memory message = abi.encode(_owner);
        BLS.G2Point memory signature = BLS.sign(message, privateKey, REGISTRATION_DOMAIN_SEPARATOR);
        signedRegistration = IRegistry.SignedRegistration({ pubkey: pubkey, signature: signature });
    }

    /// @dev NOT MEANT FOR PRODUCTION USE
    function _nRegistrations(uint256 _n, uint256 privateKeyStart, address _owner)
        internal
        view
        returns (IRegistry.SignedRegistration[] memory signedRegistrations)
    {
        signedRegistrations = new IRegistry.SignedRegistration[](_n);
        for (uint256 i = 0; i < _n; i++) {
            signedRegistrations[i] = _signTestRegistration(privateKeyStart + i, _owner);
        }
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
        view
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

    function _writeRegistrationProof(IRegistry.RegistrationProof memory proof, string memory _outfile) public {
        // Write to json outfile if specified otherwise default "output/SignedRegistrations.json"
        (string memory _jsonFile,) = _getDefaultJson(_outfile, "RegistrationProof.json");

        // Write the registrationRoot to the json file
        vm.writeJson(vm.toString(proof.registrationRoot), _jsonFile, ".registrationRoot");

        // Write the abi-encoded SignedRegistration to the json file
        vm.writeJson(vm.toString(abi.encode(proof.registration)), _jsonFile, ".registration");

        // Write the abi-encoded merklProof bytes32[] to the json file
        vm.writeJson(vm.toString(abi.encode(proof.merkleProof)), _jsonFile, ".merkleProof");

        // Write the leafIndex to the json file
        vm.writeJson(vm.toString(proof.leafIndex), _jsonFile, ".leafIndex");

        console.log("RegistrationProof written to", _jsonFile);
    }

    function _readRegistrationProof(string memory _infile)
        public
        view
        returns (IRegistry.RegistrationProof memory proof)
    {
        string memory jsonFile = string(abi.encodePacked("script/output/", _infile));
        string memory json = vm.readFile(jsonFile);
        bytes memory data = vm.parseJson(json);

        // Decode the wrapper RegistrationProofJson struct
        RegistrationProofJson memory registrationProofJson = abi.decode(data, (RegistrationProofJson));

        // Copy over to correct struct
        proof.registrationRoot = registrationProofJson.registrationRoot;

        proof.registration = abi.decode(registrationProofJson.registration, (IRegistry.SignedRegistration));

        proof.merkleProof = abi.decode(registrationProofJson.merkleProof, (bytes32[]));

        proof.leafIndex = uint256(registrationProofJson.leafIndex);
    }

    function _buildPubkeyStrings(IRegistry.SignedRegistration[] memory registrations)
        internal
        pure
        returns (string memory)
    {
        string memory s;
        for (uint256 i = 0; i < registrations.length; i++) {
            BLS.Fp memory compressed = BLS.compress(registrations[i].pubkey);
            bytes memory pubkey = abi.encode(compressed);
            bytes memory pubkeyPretty = _prettyPubKey(pubkey);
            s = string(abi.encodePacked(s, vm.toString(pubkeyPretty), ",\n"));
        }
        return s;
    }

    function _prettyPubKey(bytes memory pubkey) internal pure returns (bytes memory) {
        bytes memory pubkeyPretty = new bytes(48);
        for (uint256 j = 16; j < pubkey.length; j++) {
            pubkeyPretty[j - 16] = pubkey[j];
        }
        return pubkeyPretty;
    }
}
