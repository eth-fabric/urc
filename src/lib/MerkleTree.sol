// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "@openzeppelin/contracts/utils/math/Math.sol";
import { MerkleTreeLib } from "solady/utils/MerkleTreeLib.sol";
import { MerkleProofLib } from "solady/utils/MerkleProofLib.sol";
import { IRegistry } from "../IRegistry.sol";

/**
 * @title MerkleTree
 * @dev Implementation of a binary Merkle tree with proof generation and verification
 */
library MerkleTree {
    error EmptyLeaves();
    error IndexOutOfBounds();
    error LeavesTooLarge();
    /**
     * @dev Generates a complete Merkle tree from an array of leaves
     * @dev Will pad leaves to the next power of 2
     * @param leaves Array of leaf values
     * @return bytes32 Root hash of the Merkle tree
     */

    function generateTree(bytes32[] memory leaves) internal pure returns (bytes32) {
        return MerkleTreeLib.root(MerkleTreeLib.build(MerkleTreeLib.pad(leaves)));
    }

    /**
     * @dev Generates a Merkle proof for a leaf at the given index
     * @param leaves Array of unpadded leaf values
     * @param index Index of the leaf to generate proof for
     * @return bytes32[] Array of proof elements
     */
    function generateProof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory) {
        bytes32[] memory tree = MerkleTreeLib.build(MerkleTreeLib.pad(leaves));
        return MerkleTreeLib.leafProof(tree, index);
    }

    /**
     * @dev Verifies a Merkle proof for a leaf
     * @param root Root hash of the Merkle tree
     * @param leaf Leaf value being proved
     * @param proof Array of proof elements
     * @return bool True if the proof is valid, false otherwise
     */
    function verifyProof(bytes32 root, bytes32 leaf, bytes32[] memory proof) internal pure returns (bool) {
        return MerkleProofLib.verify(proof, root, leaf);
    }

    /**
     * @dev Verifies a Merkle proof for a leaf
     * @param root Root hash of the Merkle tree
     * @param leaf Leaf value being proved
     * @param proof Array of proof elements
     * @return bool True if the proof is valid, false otherwise
     */
    function verifyProofCalldata(bytes32 root, bytes32 leaf, bytes32[] calldata proof) internal pure returns (bool) {
        return MerkleProofLib.verifyCalldata(proof, root, leaf);
    }

    /// @notice Computes Merkle tree leaves from an array of `SignedRegistration` structs and an owner address.
    /// @dev Each leaf is computed as `keccak256(abi.encode(reg, owner))`.
    /// This function replicates the behavior of the following Solidity loop using inline assembly for gas efficiency:
    ///
    /// ```solidity
    /// bytes32[] memory leaves = new bytes32[](regs.length);
    /// for (uint256 i = 0; i < regs.length; i++) {
    ///     leaves[i] = keccak256(abi.encode(regs[i], owner));
    /// }
    /// ```
    ///
    /// The encoding consists of:
    /// - 384 bytes for the `SignedRegistration` struct (G1 + G2 BLS points)
    /// - 32 bytes for the owner address (20-byte value left-padded with 12 zero bytes)
    ///
    /// @param regs The array of `SignedRegistration` structs to hash
    /// @param owner The operator’s address to include in the leaf
    /// @return leaves The resulting array of hashed leaf nodes
    function hashToLeaves(IRegistry.SignedRegistration[] calldata regs, address owner)
        internal
        pure
        returns (bytes32[] memory leaves)
    {
        assembly {
            // --- Constants ---
            let arrayLength := regs.length // Number of SignedRegistration structs
            let structSize := 0x180 // Size of a SignedRegistration (384 bytes)
            let encodingSize := 0x1a0 // 384 bytes (struct) + 32 bytes (address padded) = 416 bytes

            // --- Allocate memory for output bytes32[] leaves ---
            leaves := mload(0x40) // Load the current free memory pointer
            let leavesSize := add(0x20, mul(arrayLength, 0x20)) // 32 bytes for length + 32 bytes per leaf
            mstore(0x40, add(leaves, leavesSize)) // Allocate memory for leaves array
            mstore(leaves, arrayLength) // Store the array length at the start of `leaves`

            // --- Allocate scratch space for encoding one (struct, address) pair ---
            let tempBuffer := mload(0x40) // Load updated free memory pointer
            mstore(0x40, add(tempBuffer, encodingSize)) // Reserve space for buffer (416 bytes)

            let leavesPtr := add(leaves, 0x20) // Pointer to first leaf slot (after length)

            // --- Loop through each SignedRegistration ---
            for { let i := 0 } lt(i, arrayLength) { i := add(i, 1) } {
                // Copy packed SignedRegistration data directly from calldata to temp buffer
                calldatacopy(tempBuffer, add(regs.offset, mul(i, structSize)), structSize)

                // Append left-padded 20-byte address to the buffer
                mstore(add(tempBuffer, structSize), owner)

                // Hash and store
                mstore(add(leavesPtr, mul(i, 0x20)), keccak256(tempBuffer, encodingSize))
            }
        }
    }
}
