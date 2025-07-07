// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/IRegistry.sol";
import "../src/lib/MerkleTree.sol";
import "../src/ISlasher.sol";
import { BLS } from "solady/utils/ext/ithaca/BLS.sol";
import { BLSUtils } from "../src/lib/BLSUtils.sol";

contract BaseScript is Script {
    bytes public constant REGISTRATION_DOMAIN_SEPARATOR = "0x00555243"; // "URC" in little endian
    bytes public constant DELEGATION_DOMAIN_SEPARATOR = "0x0044656c"; // "Del" in little endian

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

        vm.sleep(500);

        // Copy the default json object to the new file to create the file if it doesn't exist
        if (!vm.isFile(jsonFile)) {
            vm.writeFile(jsonFile, jsonObj);
            vm.sleep(500);
        }

        return (jsonFile, jsonObj);
    }

    /// @dev NOT MEANT FOR PRODUCTION USE
    function _signTestRegistration(uint256 privateKey, address _owner)
        internal
        view
        returns (IRegistry.SignedRegistration memory signedRegistration)
    {
        BLS.G1Point memory pubkey = BLSUtils.toPublicKey(privateKey);
        bytes memory message = abi.encode(_owner);
        BLS.G2Point memory signature = BLSUtils.sign(message, privateKey, REGISTRATION_DOMAIN_SEPARATOR);
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

    /// @dev NOT MEANT FOR PRODUCTION USE
    function _signTestDelegation(uint256 privateKey, ISlasher.Delegation memory delegation)
        internal
        view
        returns (ISlasher.SignedDelegation memory signedDelegation)
    {
        BLS.G2Point memory signature = BLSUtils.sign(abi.encode(delegation), privateKey, DELEGATION_DOMAIN_SEPARATOR);
        return ISlasher.SignedDelegation({ delegation: delegation, signature: signature });
    }

    /// @dev NOT MEANT FOR PRODUCTION USE
    function _nDelegations(
        uint256 _n,
        uint256 _proposerPrivateKey,
        uint256 _delegatePrivateKeyStart,
        address _committer,
        uint256 _slot
    ) internal view returns (ISlasher.SignedDelegation[] memory signedDelegations) {
        BLS.G1Point memory proposer = BLSUtils.toPublicKey(_proposerPrivateKey);
        signedDelegations = new ISlasher.SignedDelegation[](_n);
        for (uint256 i = 0; i < _n; i++) {
            BLS.G1Point memory delegate = BLSUtils.toPublicKey(_delegatePrivateKeyStart + i);
            signedDelegations[i] = _signTestDelegation(
                _proposerPrivateKey, // fixed proposer private key
                ISlasher.Delegation({
                    proposer: proposer,
                    delegate: delegate, // different delegate for each delegation
                    committer: _committer,
                    slot: uint64(_slot),
                    metadata: ""
                })
            );
        }
    }

    /// @dev NOT MEANT FOR PRODUCTION USE
    function _signTestCommitment(uint256 privateKey, address slasher, uint256 commitmentType, bytes memory payload)
        internal
        pure
        returns (ISlasher.SignedCommitment memory signedCommitment)
    {
        ISlasher.Commitment memory commitment =
            ISlasher.Commitment({ commitmentType: uint64(commitmentType), payload: payload, slasher: slasher });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, keccak256(abi.encode(commitment)));
        bytes memory signature = abi.encodePacked(r, s, v);
        return ISlasher.SignedCommitment({ commitment: commitment, signature: signature });
    }

    function _writeSignedRegistrations(
        address _owner,
        IRegistry.SignedRegistration[] memory _registrations,
        string memory _outfile
    ) public {
        // Write to json outfile if specified otherwise default "output/SignedRegistrations.json"
        (string memory _jsonFile,) = _getDefaultJson(_outfile, "SignedRegistrations.json");

        // Encode the signed registrations as abi-encoded bytes
        vm.writeJson(vm.toString(abi.encode(_registrations)), _jsonFile, ".signedRegistrations");
        vm.sleep(250);

        // Write the owner address to the json file
        vm.writeJson(vm.toString(_owner), _jsonFile, ".owner");
        vm.sleep(250);

        console.log("SignedRegistrations written to", _jsonFile);
    }

    function _readSignedRegistrations(string memory _infile)
        public
        returns (address owner, IRegistry.SignedRegistration[] memory)
    {
        string memory jsonFile = string(abi.encodePacked("script/output/", _infile));
        string memory json = vm.readFile(jsonFile);

        vm.sleep(500);

        // Decode the SignedRegistration[]
        IRegistry.SignedRegistration[] memory registrations =
            abi.decode(vm.parseJsonBytes(json, ".signedRegistrations"), (IRegistry.SignedRegistration[]));

        // Decode the owner address
        owner = vm.parseJsonAddress(json, ".owner");

        console.log("Owner address:", owner);
        console.log("Total signed registrations:", registrations.length);
        console.log("Pubkeys:");
        for (uint256 i = 0; i < registrations.length; i++) {
            _prettyPrintPubKey(registrations[i]);
        }

        return (owner, registrations);
    }

    function _writeRegistrationProof(IRegistry.RegistrationProof memory proof, string memory _outfile) public {
        // Write to json outfile if specified otherwise default "output/SignedRegistrations.json"
        (string memory _jsonFile,) = _getDefaultJson(_outfile, "RegistrationProof.json");

        // Write the abi-encoded merklProof bytes32[] to the json file
        vm.writeJson(vm.toString(abi.encode(proof.merkleProof)), _jsonFile, ".merkleProof");
        vm.sleep(250);

        // Write the abi-encoded SignedRegistration to the json file
        vm.writeJson(vm.toString(abi.encode(proof.registration)), _jsonFile, ".registration");
        vm.sleep(250);

        // Write the registrationRoot to the json file
        vm.writeJson(vm.toString(proof.registrationRoot), _jsonFile, ".registrationRoot");
        vm.sleep(250);

        console.log("RegistrationProof written to", _jsonFile);
    }

    function _readRegistrationProof(string memory _infile) public returns (IRegistry.RegistrationProof memory proof) {
        string memory jsonFile = string(abi.encodePacked("script/output/", _infile));
        string memory json = vm.readFile(jsonFile);

        vm.sleep(500);

        proof.merkleProof = abi.decode(vm.parseJsonBytes(json, ".merkleProof"), (bytes32[]));

        proof.registration = abi.decode(vm.parseJsonBytes(json, ".registration"), (IRegistry.SignedRegistration));

        proof.registrationRoot = vm.parseJsonBytes32(json, ".registrationRoot");
    }

    function _writeDelegation(ISlasher.SignedDelegation memory delegation, string memory outfile) internal {
        // Write to json outfile if specified otherwise default "output/Delegation.json"
        (string memory jsonFile,) = _getDefaultJson(outfile, "Delegation.json");
        vm.sleep(250);

        vm.writeJson(vm.toString(abi.encode(delegation.delegation.committer)), jsonFile, ".committer");
        vm.sleep(250);

        vm.writeJson(vm.toString(abi.encode(delegation.delegation.delegate)), jsonFile, ".delegate");
        vm.sleep(250);

        vm.writeJson(vm.toString(abi.encode(delegation.delegation.metadata)), jsonFile, ".metadata");
        vm.sleep(250);

        vm.writeJson(vm.toString(abi.encode(delegation.delegation.proposer)), jsonFile, ".proposer");
        vm.sleep(250);

        vm.writeJson(vm.toString(abi.encode(delegation.signature)), jsonFile, ".signature");

        vm.writeJson(vm.toString(delegation.delegation.slot), jsonFile, ".slot");
        vm.sleep(250);

        console.log("Delegation written to", jsonFile);
    }

    function _readDelegation(string memory infile) internal returns (ISlasher.SignedDelegation memory delegation) {
        string memory jsonFile = string(abi.encodePacked("script/output/", infile));
        string memory json = vm.readFile(jsonFile);

        vm.sleep(500);

        delegation.delegation.committer = abi.decode(vm.parseJsonBytes(json, ".committer"), (address));
        delegation.delegation.delegate = abi.decode(vm.parseJsonBytes(json, ".delegate"), (BLS.G1Point));
        delegation.delegation.metadata = abi.decode(vm.parseJsonBytes(json, ".metadata"), (bytes));
        delegation.delegation.proposer = abi.decode(vm.parseJsonBytes(json, ".proposer"), (BLS.G1Point));
        delegation.signature = abi.decode(vm.parseJsonBytes(json, ".signature"), (BLS.G2Point));
        delegation.delegation.slot = uint64(vm.parseJsonUint(json, ".slot"));
    }

    function _writeCommitment(ISlasher.SignedCommitment memory commitment, string memory outfile) internal {
        // Write to json outfile if specified otherwise default "output/Commitment.json"
        (string memory jsonFile,) = _getDefaultJson(outfile, "Commitment.json");
        vm.sleep(250);

        vm.writeJson(vm.toString(commitment.commitment.commitmentType), jsonFile, ".commitmentType");
        vm.sleep(250);

        vm.writeJson(vm.toString(abi.encode(commitment.commitment.slasher)), jsonFile, ".slasher");
        vm.sleep(250);

        vm.writeJson(vm.toString(commitment.commitment.payload), jsonFile, ".payload");
        vm.sleep(250);

        vm.writeJson(vm.toString(commitment.signature), jsonFile, ".signature");

        console.log("Commitment written to", jsonFile);
    }

    function _readCommitment(string memory infile) internal returns (ISlasher.SignedCommitment memory commitment) {
        string memory jsonFile = string(abi.encodePacked("script/output/", infile));
        string memory json = vm.readFile(jsonFile);

        vm.sleep(500);

        commitment.commitment.commitmentType = uint64(vm.parseJsonUint(json, ".commitmentType"));
        commitment.commitment.payload = vm.parseJsonBytes(json, ".payload");
        commitment.commitment.slasher = abi.decode(vm.parseJsonBytes(json, ".slasher"), (address));
        commitment.signature = vm.parseJsonBytes(json, ".signature");
    }

    function _buildPubkeyStrings(IRegistry.SignedRegistration[] memory registrations)
        internal
        pure
        returns (string memory)
    {
        string memory s;
        for (uint256 i = 0; i < registrations.length; i++) {
            BLS.G1Point memory pubkeyCopy = BLS.G1Point(
                registrations[i].pubkey.x_a,
                registrations[i].pubkey.x_b,
                registrations[i].pubkey.y_a,
                registrations[i].pubkey.y_b
            );
            BLS.Fp memory compressed = BLSUtils.compress(pubkeyCopy);
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

    function _prettyPrintPubKey(IRegistry.SignedRegistration memory registration) internal {
        // duplicate to prevent weird foundry memory issues
        BLS.G1Point memory pubkeyCopy = BLS.G1Point(
            registration.pubkey.x_a, registration.pubkey.x_b, registration.pubkey.y_a, registration.pubkey.y_b
        );
        bytes memory pubkeyPretty = _prettyPubKey(abi.encode(BLSUtils.compress(pubkeyCopy)));
        console.log("Pubkey: ", vm.toString(pubkeyPretty));
    }
}
