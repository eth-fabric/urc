// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/lib/MerkleTree.sol";
import { MerkleTreeLib } from "solady/utils/MerkleTreeLib.sol";

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
                MerkleTree.verifyProof(root, largeTree[i], proof),
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
            assertTrue(MerkleTree.verifyProof(root, randomLeaves[i], proof), "Random leaf verification failed");
        }
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
                    MerkleTree.verifyProof(root, leaves[indicesToCheck[k]], proof),
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
                    MerkleTree.verifyProof(root, leaves[j], proof),
                    string.concat("Tree ", vm.toString(i), " failed at leaf ", vm.toString(j))
                );
            }
        }
    }
}

contract Foo {
    using MerkleTree for bytes32[];

    function generateTree(bytes32[] calldata leaves) public pure returns (bytes32) {
        return leaves.generateTree();
    }
}

contract MerkleTreeGasTest is Test {
    using MerkleTree for bytes32[];

    Foo foo;

    function setUp() public {
        foo = new Foo();
    }

    function getLeaves(uint256 size) public pure returns (bytes32[] memory) {
        bytes32[] memory leaves = new bytes32[](size);
        for (uint256 i = 0; i < size; i++) {
            leaves[i] = keccak256(abi.encodePacked(i));
        }
        return leaves;
    }

    function test_gas_generateTree_1() public {
        bytes32[] memory leaves = getLeaves(1);
        vm.resetGasMetering();
        foo.generateTree(leaves);
    }

    function test_gas_generateTree_2() public {
        bytes32[] memory leaves = getLeaves(2);
        vm.resetGasMetering();
        foo.generateTree(leaves);
    }

    function test_gas_generateTree_4() public {
        bytes32[] memory leaves = getLeaves(4);
        vm.resetGasMetering();
        foo.generateTree(leaves);
    }

    function test_gas_generateTree_8() public {
        bytes32[] memory leaves = getLeaves(8);
        vm.resetGasMetering();
        foo.generateTree(leaves);
    }

    function test_gas_generateTree_16() public {
        bytes32[] memory leaves = getLeaves(16);
        vm.resetGasMetering();
        foo.generateTree(leaves);
    }

    function test_gas_generateTree_32() public {
        bytes32[] memory leaves = getLeaves(32);
        vm.resetGasMetering();
        foo.generateTree(leaves);
    }

    function test_gas_generateTree_64() public {
        bytes32[] memory leaves = getLeaves(64);
        vm.resetGasMetering();
        foo.generateTree(leaves);
    }

    function test_gas_generateTree_128() public {
        bytes32[] memory leaves = getLeaves(128);
        vm.resetGasMetering();
        foo.generateTree(leaves);
    }

    function test_gas_generateTree_256() public {
        bytes32[] memory leaves = getLeaves(256);
        vm.resetGasMetering();
        foo.generateTree(leaves);
    }

    function test_gas_generateTree_512() public {
        bytes32[] memory leaves = getLeaves(512);
        vm.resetGasMetering();
        foo.generateTree(leaves);
    }

    function test_gas_generateTree_1024() public {
        bytes32[] memory leaves = getLeaves(1024);
        vm.resetGasMetering();
        foo.generateTree(leaves);
    }
}

contract Bar {
    using MerkleTree for bytes32[];

    function build(bytes32[] calldata leaves) public pure returns (bytes32[] memory) {
        return MerkleTreeLib.build(leaves);
    }
}

// Test the gas consumption of the Solady build() function
contract MerkleTreeBuildGasTest is Test {
    using MerkleTreeLib for bytes32[];

    Bar bar;

    function setUp() public {
        bar = new Bar();
    }

    function getLeaves(uint256 size) public pure returns (bytes32[] memory) {
        bytes32[] memory leaves = new bytes32[](size);
        for (uint256 i = 0; i < size; i++) {
            leaves[i] = keccak256(abi.encodePacked(i));
        }
        return leaves;
    }

    function test_gas_buildTree_1() public {
        bytes32[] memory leaves = getLeaves(1);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_2() public {
        bytes32[] memory leaves = getLeaves(2);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_4() public {
        bytes32[] memory leaves = getLeaves(4);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_8() public {
        bytes32[] memory leaves = getLeaves(8);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_16() public {
        bytes32[] memory leaves = getLeaves(16);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_32() public {
        bytes32[] memory leaves = getLeaves(32);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_64() public {
        bytes32[] memory leaves = getLeaves(64);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_128() public {
        bytes32[] memory leaves = getLeaves(128);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_256() public {
        bytes32[] memory leaves = getLeaves(256);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_512() public {
        bytes32[] memory leaves = getLeaves(512);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_1024() public {
        bytes32[] memory leaves = getLeaves(1024);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_2048() public {
        bytes32[] memory leaves = getLeaves(2048);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_4096() public {
        bytes32[] memory leaves = getLeaves(4096);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_8192() public {
        bytes32[] memory leaves = getLeaves(8192);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_16384() public {
        bytes32[] memory leaves = getLeaves(16384);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_32768() public {
        bytes32[] memory leaves = getLeaves(32768);
        vm.resetGasMetering();
        bar.build(leaves);
    }

    function test_gas_buildTree_65536() public {
        bytes32[] memory leaves = getLeaves(65536);
        vm.resetGasMetering();
        bar.build(leaves);
    }
}
