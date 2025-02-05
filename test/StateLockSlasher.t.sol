// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

// Adapted from https://github.com/chainbound/bolt/tree/unstable/bolt-contracts

import { console } from "forge-std/Test.sol";

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { RLPReader } from "../example/lib/rlp/RLPReader.sol";
import { RLPWriter } from "../example/lib/rlp/RLPWriter.sol";
import { BytesUtils } from "../example/lib/BytesUtils.sol";
import { MerkleTrie } from "../example/lib/trie/MerkleTrie.sol";
import { SecureMerkleTrie } from "../example/lib/trie/SecureMerkleTrie.sol";
import { TransactionDecoder } from "../example/lib/TransactionDecoder.sol";
import { Registry } from "../src/Registry.sol";
import { IRegistry } from "../src/IRegistry.sol";
import { ISlasher } from "../src/ISlasher.sol";
import { BLS } from "../src/lib/BLS.sol";
import { MerkleTree } from "../src/lib/MerkleTree.sol";
import { PreconfStructs } from "../example/PreconfStructs.sol";
import { StateLockSlasher } from "../example/StateLockSlasher.sol";
import { UnitTestHelper } from "./UnitTestHelper.sol";

contract StateLockSlasherTest is UnitTestHelper, PreconfStructs {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using BytesUtils for bytes;
    using TransactionDecoder for TransactionDecoder.Transaction;
    using TransactionDecoder for bytes;

    StateLockSlasher slasher;
    BLS.G1Point delegatePubKey;
    uint256 slashAmountGwei = 1 ether / 1 gwei; // slash 1 ether
    uint256 collateral = 1.1 ether;
    uint256 committerSecretKey;
    address committer;

    function setUp() public {
        vm.createSelectFork(vm.rpcUrl("mainnet"));
        slasher = new StateLockSlasher(slashAmountGwei);
        registry = new Registry();
        (committer, committerSecretKey) = makeAddrAndKey("commitmentsKey");
        delegatePubKey = BLS.toPublicKey(SECRET_KEY_2);
        vm.deal(committer, 100 ether);
    }

    function testProveTransactionInclusion() public {
        // The transaction we want to prove inclusion of
        bytes32 txHash = 0x9ec2c56ca36e445a46bc77ca77510f0ef21795d00834269f3752cbd29d63ba1f;

        // MPT proof, obtained with the `trie-proofs` CLI tool from HerodotusDev
        // ref: <https://github.com/HerodotusDev/trie-proofs>
        string memory file = vm.readFile("./test/testdata/tx_mpt_proof_20785012.json");
        bytes[] memory txProofJson = vm.parseJsonBytesArray(file, ".proof");
        bytes memory txProof = _RLPEncodeList(txProofJson);

        // The transactions root and index in the block, also included in the CLI response
        bytes32 txRootAtBlock = vm.parseJsonBytes32(file, ".root");
        uint256 txIndexInBlock = vm.parseJsonUint(file, ".index");

        bytes memory key = RLPWriter.writeUint(txIndexInBlock);

        vm.resumeGasMetering();
        // Gotcha: SecureMerkleTrie.get expects the key to be hashed with keccak256
        // but the transaction trie skips this step and uses the raw index as the key.
        (bool exists, bytes memory transactionRLP) = MerkleTrie.get(key, txProof, txRootAtBlock);
        vm.pauseGasMetering();

        assertEq(exists, true);
        assertEq(keccak256(transactionRLP), txHash);

        // Decode the transaction RLP into its fields
        TransactionDecoder.Transaction memory decodedTx = transactionRLP.decodeEnveloped();
        assertEq(uint8(decodedTx.txType), 2);
        assertEq(decodedTx.chainId, 1);
        assertEq(decodedTx.nonce, 0xeb);
        assertEq(decodedTx.maxPriorityFeePerGas, 0x73a20d00);
        assertEq(decodedTx.maxFeePerGas, 0x7e172a822);
        assertEq(decodedTx.gasLimit, 0x5208);
        assertEq(decodedTx.to, 0x0ff71973B5243005b192D5BCF552Fc2532b7bdEc);
        assertEq(decodedTx.value, 0x15842095ebc4000);
        assertEq(decodedTx.data.length, 0);
        assertEq(decodedTx.recoverSender(), 0x0D9f5045B604bA0c050b5eb06D0b25d01c525Ea5);
    }

    function testCommitmentSignature() public {
        bytes memory signedTx = vm.parseJsonBytes(vm.readFile("./test/testdata/signed_tx_20785012_1.json"), ".raw");
        uint64 slot = 20_728_344;

        // Reconstruct the commitment digest
        bytes32 commitmentID = _computeCommitmentID(signedTx, slot);

        // Sign the commitment digest with the target
        (address target, uint256 targetPK) = makeAddrAndKey("target");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(targetPK, commitmentID);
        bytes memory commitmentSignature = abi.encodePacked(r, s, v);

        // Verify the commitment signature against the digest
        vm.resumeGasMetering();
        address commitmentSigner = ECDSA.recover(commitmentID, commitmentSignature);
        assertEq(commitmentSigner, target);
        vm.pauseGasMetering();
    }

    function setupRegistration(address operator, address delegate, uint64 slot)
        internal
        returns (RegisterAndDelegateResult memory result)
    {
        // Prepare the metadata for the delegation, delegating to the delegate to sign exclusion commitments
        bytes memory metadata = abi.encode(delegate);

        // Register operator to URC
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(slasher),
            metadata: metadata,
            slot: slot
        });

        // Register operator to URC and signs delegation message
        result = registerAndDelegate(params);
    }

    function setupSlash(uint256 id)
        public
        returns (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            bytes memory evidence
        )
    {
        uint256 exclusionBlockNumber = 20_785_012;
        // Create new keypair and fund wallet
        (address alice, uint256 alicePK) = makeAddrAndKey(string.concat("alice_", vm.toString(id)));
        vm.deal(alice, 100 ether); // Give alice some ETH

        // Advance before the fraud proof window
        vm.roll(exclusionBlockNumber - registry.FRAUD_PROOF_WINDOW());
        vm.warp(exclusionBlockNumber - registry.FRAUD_PROOF_WINDOW() * 12);

        // Register and delegate
        result = setupRegistration(alice, delegate, 9994114 - 100);

        // Advance over registration fraud proof window to the target slot
        vm.roll(exclusionBlockNumber);
        vm.warp(slasher._getTimestampFromSlot(9994114)); // https://etherscan.io/block/20785012

        // Register and delegate
        // Delegate signs a commitment to exclude a TX
        TransactionCommitment memory commitment =
            _createStateLockCommitment(exclusionBlockNumber, id, committer, committerSecretKey);

        // Build the inclusion proof to prove failure to exclude
        string memory rawPreviousHeader = vm.readFile("./test/testdata/header_20785011.json");
        string memory rawInclusionHeader = vm.readFile("./test/testdata/header_20785012.json");
        string memory ethProof = vm.readFile("./test/testdata/eth_proof_20785011.json");
        string memory txProof = vm.readFile("./test/testdata/tx_mpt_proof_20785012.json");

        bytes[] memory txProofs = new bytes[](1);
        txProofs[0] = _RLPEncodeList(vm.parseJsonBytesArray(txProof, ".proof"));

        uint256[] memory txIndexesInBlock = new uint256[](1);
        txIndexesInBlock[0] = vm.parseJsonUint(txProof, ".index");

        InclusionProof memory inclusionProof = InclusionProof({
            inclusionBlockNumber: exclusionBlockNumber,
            previousBlockHeaderRLP: vm.parseJsonBytes(rawPreviousHeader, ".result"),
            inclusionBlockHeaderRLP: vm.parseJsonBytes(rawInclusionHeader, ".result"),
            accountMerkleProof: _RLPEncodeList(vm.parseJsonBytesArray(ethProof, ".result.accountProof")),
            txMerkleProofs: txProofs,
            txIndexesInBlock: txIndexesInBlock
        });

        // check that the inclusion block transactions root matches the root in the tx proof data.
        bytes32 inclusionTxRoot = slasher._decodeBlockHeaderRLP(inclusionProof.inclusionBlockHeaderRLP).txRoot;
        assertEq(inclusionTxRoot, vm.parseJsonBytes32(txProof, ".root"));

        signedCommitment = basicCommitment(committerSecretKey, address(slasher), abi.encode(commitment));

        evidence = abi.encode(inclusionProof);
    }

    function test_slash() public {
        // Register at URC and generate slashable evidence
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            bytes memory evidence
        ) = setupSlash(1);

        // Merkle proof for URC registration
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory registrationProof = MerkleTree.generateProof(leaves, leafIndex);

        // Save for comparison after slashing
        uint256 challengerBalanceBefore = challenger.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // Slash via URC
        vm.startPrank(challenger);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[0].signature,
            registrationProof,
            leafIndex,
            result.signedDelegation,
            signedCommitment,
            evidence
        );

        _verifySlashCommitmentBalances(
            challenger, slashAmountGwei * 1 gwei, 0, challengerBalanceBefore, urcBalanceBefore
        );

        // Retrieve operator data
        OperatorData memory operatorData = getRegistrationData(result.registrationRoot);

        // Verify operator's slashedAt is set
        assertEq(operatorData.slashedAt, block.number, "slashedAt not set");

        // Verify operator's collateralGwei is decremented
        assertEq(operatorData.collateralGwei, collateral / 1 gwei - slashAmountGwei, "collateralGwei not decremented");

        // Verify the slashedBefore mapping is set
        bytes32 slashingDigest =
            keccak256(abi.encode(result.signedDelegation, signedCommitment, result.registrationRoot));
        assertEq(registry.slashedBefore(slashingDigest), true, "slashedBefore not set");
    }

    // =========== Helper functions ===========

    // Helper to create a test inclusion proof with a recent slot, valid for a recent challenge
    function _createStateLockCommitment(uint256 blockNumber, uint256 id, address delegate, uint256 delegatePK)
        internal
        view
        returns (TransactionCommitment memory commitment)
    {
        // pattern: ./test/testdata/signed_tx_{blockNumber}_{id}.json
        string memory base = "./test/testdata/signed_tx_";
        string memory extension = string.concat(vm.toString(blockNumber), "_", vm.toString(id), ".json");
        string memory path = string.concat(base, extension);
        commitment.signedTx = vm.parseJsonBytes(vm.readFile(path), ".raw");

        commitment.slot = uint64(slasher._getCurrentSlot() - 100);

        // sign the new commitment with the target's private key
        bytes32 commitmentID = _computeCommitmentID(commitment.signedTx, commitment.slot);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(delegatePK, commitmentID);
        commitment.signature = abi.encodePacked(r, s, v);

        // Normalize v to 27 or 28
        if (uint8(commitment.signature[64]) < 27) {
            commitment.signature[64] = bytes1(uint8(commitment.signature[64]) + 0x1B);
        }

        // Sanity check
        assertEq(ECDSA.recover(commitmentID, commitment.signature), delegate);

        return commitment;
    }

    // Helper to compute the commitment ID
    function _computeCommitmentID(bytes memory signedTx, uint64 slot) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(signedTx), _toLittleEndian(slot)));
    }

    // Helper to encode a list of bytes[] into an RLP list with each item RLP-encoded
    function _RLPEncodeList(bytes[] memory _items) internal pure returns (bytes memory) {
        bytes[] memory encodedItems = new bytes[](_items.length);
        for (uint256 i = 0; i < _items.length; i++) {
            encodedItems[i] = RLPWriter.writeBytes(_items[i]);
        }
        return RLPWriter.writeList(encodedItems);
    }

    // Helper to convert a u64 to a little-endian bytes
    function _toLittleEndian(uint64 x) internal pure returns (bytes memory) {
        bytes memory b = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            b[i] = bytes1(uint8(x >> (8 * i)));
        }
        return b;
    }
}
