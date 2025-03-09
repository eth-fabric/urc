// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/lib/MerkleTree.sol";

contract MerkleTreeTest is Test {
    using MerkleTree for bytes32[];

    bytes32[] standardLeaves;

    function setUp() public {
        standardLeaves = new bytes32[](4);
        standardLeaves[0] = keccak256(abi.encodePacked("leaf1"));
        standardLeaves[1] = keccak256(abi.encodePacked("leaf2"));
        standardLeaves[2] = keccak256(abi.encodePacked("leaf3"));
        standardLeaves[3] = keccak256(abi.encodePacked("leaf4"));
    }

    function testTreeConstruction(uint8 s) public pure {
        vm.assume(s > 0);
        uint256 size = uint256(s);

        bytes32[] memory largeTree = new bytes32[](size);

        // Fill with incremental hashes
        for (uint256 i = 0; i < size; i++) {
            largeTree[i] = keccak256(abi.encodePacked(i));
        }

        bytes32 root = largeTree.generateTree();

        // Verify every leaf
        for (uint256 i = 0; i < size; i++) {
            bytes32[] memory proof = largeTree.generateProof(i);
            assertTrue(
                MerkleTree.verifyProof(root, largeTree[i], i, proof),
                string.concat("Large tree verification failed at index ", vm.toString(i))
            );
        }
    }

    function testRandomizedLeaves(uint8 s) public view {
        vm.assume(s > 0);
        uint256 size = uint256(s);
        // Create tree with random data
        bytes32[] memory randomLeaves = new bytes32[](size);

        for (uint256 i = 0; i < size; i++) {
            randomLeaves[i] = bytes32(uint256(keccak256(abi.encodePacked(block.timestamp, i, s))));
        }

        bytes32 root = randomLeaves.generateTree();

        // Test proofs
        for (uint256 i = 0; i < size; i++) {
            bytes32[] memory proof = randomLeaves.generateProof(i);
            assertTrue(MerkleTree.verifyProof(root, randomLeaves[i], i, proof), "Random leaf verification failed");
        }
    }

    function testMaliciousProofs() public view {
        bytes32 root = standardLeaves.generateTree();
        bytes32[] memory proof = standardLeaves.generateProof(0);

        // Test 1: Wrong leaf
        assertFalse(
            MerkleTree.verifyProof(
                root,
                bytes32(uint256(0x1234)), // Wrong leaf
                0,
                proof
            ),
            "Should reject wrong leaf"
        );

        // Test 2: Wrong index
        assertFalse(
            MerkleTree.verifyProof(
                root,
                standardLeaves[0],
                1, // Wrong index
                proof
            ),
            "Should reject wrong index"
        );

        // Test 3: Tampered proof
        bytes32[] memory tamperedProof = proof;
        tamperedProof[0] = bytes32(uint256(0x5678)); // Tamper with proof
        assertFalse(MerkleTree.verifyProof(root, standardLeaves[0], 0, tamperedProof), "Should reject tampered proof");

        // Test 4: Wrong length proof
        bytes32[] memory wrongLengthProof = new bytes32[](proof.length + 1);
        for (uint256 i = 0; i < proof.length; i++) {
            wrongLengthProof[i] = proof[i];
        }
        wrongLengthProof[proof.length] = bytes32(0);
        assertFalse(
            MerkleTree.verifyProof(root, standardLeaves[0], 0, wrongLengthProof), "Should reject wrong length proof"
        );
    }

    function testBoundaryTrees() public pure {
        // Test with different sizes near powers of 2
        uint256[] memory sizes = new uint256[](6);
        sizes[0] = 3; // Just under 4
        sizes[1] = 4; // Exactly 4
        sizes[2] = 5; // Just over 4
        sizes[3] = 7; // Just under 8
        sizes[4] = 8; // Exactly 8
        sizes[5] = 9; // Just over 8

        for (uint256 i = 0; i < sizes.length; i++) {
            bytes32[] memory leaves = new bytes32[](sizes[i]);
            for (uint256 j = 0; j < sizes[i]; j++) {
                leaves[j] = keccak256(abi.encodePacked(j));
            }

            bytes32 root = leaves.generateTree();

            // Verify first leaf, middle leaf, and last leaf
            uint256[] memory indicesToCheck = new uint256[](3);
            indicesToCheck[0] = 0; // First
            indicesToCheck[1] = sizes[i] / 2; // Middle
            indicesToCheck[2] = sizes[i] - 1; // Last

            for (uint256 k = 0; k < indicesToCheck.length; k++) {
                bytes32[] memory proof = leaves.generateProof(indicesToCheck[k]);
                assertTrue(
                    MerkleTree.verifyProof(root, leaves[indicesToCheck[k]], indicesToCheck[k], proof),
                    string.concat(
                        "Boundary tree size ",
                        vm.toString(sizes[i]),
                        " failed at index ",
                        vm.toString(indicesToCheck[k])
                    )
                );
            }
        }
    }

    function testConsecutiveTreeGeneration() public pure {
        bytes32[] memory leaves = new bytes32[](4);
        bytes32 lastRoot;

        // Generate multiple trees with incremental data
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = 0; j < 4; j++) {
                leaves[j] = keccak256(abi.encodePacked(i, j));
            }

            bytes32 root = leaves.generateTree();
            if (i > 0) {
                assertTrue(root != lastRoot, "Consecutive trees should have different roots");
            }
            lastRoot = root;

            // Verify all leaves
            for (uint256 j = 0; j < 4; j++) {
                bytes32[] memory proof = leaves.generateProof(j);
                assertTrue(
                    MerkleTree.verifyProof(root, leaves[j], j, proof),
                    string.concat("Tree ", vm.toString(i), " failed at leaf ", vm.toString(j))
                );
            }
        }
    }

     function testLeavesTooLarge() public {
      bytes32[] memory leaves = new bytes32[](257);
    
    // Use a try-catch pattern instead of vm.expectRevert
    bool didRevert = false;
    try this.callGenerateTree(leaves) {
        // If we reach here, no revert happened
    } catch Error(string memory reason) {
        // This catches require/revert with reason string
        didRevert = true;
    } catch (bytes memory returnData) {
        // This catches custom errors and panics
        bytes4 selector = bytes4(returnData);
        assertTrue(
            selector == MerkleTree.LeavesTooLarge.selector,
            "Wrong error selector"
        );
        didRevert = true;
    }
    
    assertTrue(didRevert, "Function did not revert with LeavesTooLarge");
}

// External function to call from try-catch
  function callGenerateTree(bytes32[] memory leaves) external pure returns (bytes32) {
    return leaves.generateTree();
}

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function testNextPowerOfTwo() public pure {
        assertEq(MerkleTree.nextPowerOfTwo(1), 1, "nextPowerOfTwo(1) should be 1");
        assertEq(MerkleTree.nextPowerOfTwo(2), 2, "nextPowerOfTwo(2) should be 2");
        assertEq(MerkleTree.nextPowerOfTwo(3), 4, "nextPowerOfTwo(3) should be 4");
        assertEq(MerkleTree.nextPowerOfTwo(4), 4, "nextPowerOfTwo(4) should be 4");
        assertEq(MerkleTree.nextPowerOfTwo(5), 8, "nextPowerOfTwo(5) should be 8");
        assertEq(MerkleTree.nextPowerOfTwo(8), 8, "nextPowerOfTwo(8) should be 8");
        assertEq(MerkleTree.nextPowerOfTwo(9), 16, "nextPowerOfTwo(9) should be 16");
        assertEq(MerkleTree.nextPowerOfTwo(16), 16, "nextPowerOfTwo(16) should be 16");
        assertEq(MerkleTree.nextPowerOfTwo(17), 32, "nextPowerOfTwo(17) should be 32");
        assertEq(MerkleTree.nextPowerOfTwo(31), 32, "nextPowerOfTwo(31) should be 32");
        assertEq(MerkleTree.nextPowerOfTwo(32), 32, "nextPowerOfTwo(32) should be 32");
        assertEq(MerkleTree.nextPowerOfTwo(33), 64, "nextPowerOfTwo(33) should be 64");
        assertEq(MerkleTree.nextPowerOfTwo(64), 64, "nextPowerOfTwo(64) should be 64");
        assertEq(MerkleTree.nextPowerOfTwo(65), 128, "nextPowerOfTwo(65) should be 128");
        assertEq(MerkleTree.nextPowerOfTwo(66), 128, "nextPowerOfTwo(66) should be 128");
        assertEq(MerkleTree.nextPowerOfTwo(128), 128, "nextPowerOfTwo(128) should be 128");
        assertEq(MerkleTree.nextPowerOfTwo(129), 256, "nextPowerOfTwo(129) should be 256");
        assertEq(MerkleTree.nextPowerOfTwo(256), 256, "nextPowerOfTwo(256) should be 256");
    }

    function testEfficientKeccak256(bytes32 a, bytes32 b) public pure {
        assertEq(
            MerkleTree._efficientKeccak256(a, b),
            keccak256(abi.encode(a, b)),
            "keccak256(a, b) should be keccak256(abi.encode(a, b))"
        );
    }
}
