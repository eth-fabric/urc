// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/IRegistry.sol";

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
}
