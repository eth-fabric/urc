// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "@openzeppelin/contracts/utils/math/Math.sol";
import { MerkleTreeLib } from "solady/utils/MerkleTreeLib.sol";
import { MerkleProofLib } from "solady/utils/MerkleProofLib.sol";

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
     * @param index Index of the leaf in the tree
     * @param proof Array of proof elements
     * @return bool True if the proof is valid, false otherwise
     */
    function verifyProof(
        bytes32 root,
        bytes32 leaf,
        uint256 index, // todo remove
        bytes32[] memory proof
    ) internal pure returns (bool) {
        return MerkleProofLib.verify(proof, root, leaf);
    }

    /**
     * @dev Verifies a Merkle proof for a leaf
     * @param root Root hash of the Merkle tree
     * @param leaf Leaf value being proved
     * @param index Index of the leaf in the tree
     * @param proof Array of proof elements
     * @return bool True if the proof is valid, false otherwise
     */
    function verifyProofCalldata(
        bytes32 root,
        bytes32 leaf,
        uint256 index, // todo remove
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        return MerkleProofLib.verifyCalldata(proof, root, leaf);
    }
}
