// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/IRegistry.sol";
import "../src/lib/MerkleTree.sol";
import "../src/lib/BLS.sol";

contract BaseScript is Script {
    bytes public constant REGISTRATION_DOMAIN_SEPARATOR = "0x00555243"; // "URC" in little endian

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
