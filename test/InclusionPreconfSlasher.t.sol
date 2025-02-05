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
import { InclusionPreconfSlasher } from "../example/InclusionPreconfSlasher.sol";
import { UnitTestHelper } from "./UnitTestHelper.sol";

contract InclusionPreconfSlasherTest is UnitTestHelper, PreconfStructs {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using BytesUtils for bytes;
    using TransactionDecoder for TransactionDecoder.Transaction;
    using TransactionDecoder for bytes;

    InclusionPreconfSlasher slasher;
    BLS.G1Point delegatePubKey;
    uint256 slashAmountGwei = 1 ether / 1 gwei; // slash 1 ether
    uint256 collateral = 1.1 ether;
    uint256 committerSecretKey;
    address committer;

    function setUp() public {
        vm.createSelectFork(vm.rpcUrl("mainnet"));
        registry = new Registry();
        slasher = new InclusionPreconfSlasher(slashAmountGwei, address(registry));
        delegatePubKey = BLS.toPublicKey(SECRET_KEY_2);
        (committer, committerSecretKey) = makeAddrAndKey("commitmentsKey");
        vm.deal(challenger, 100 ether);
        vm.deal(operator, 100 ether);
        vm.deal(committer, 100 ether);
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
        vm.prank(operator);
        result = registerAndDelegate(params);
    }

    function setupSlash(uint256 id)
        public
        returns (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            PreconfStructs.InclusionProof memory inclusionProof
        )
    {
        uint256 inclusionBlockNumber = 20_785_012;

        // Advance before the fraud proof window
        vm.roll(inclusionBlockNumber - registry.FRAUD_PROOF_WINDOW());
        vm.warp(inclusionBlockNumber - registry.FRAUD_PROOF_WINDOW() * 12);

        // Register and delegate
        result = setupRegistration(operator, delegate, 9994114 - 100);

        // Advance over registration fraud proof window to the target slot
        vm.roll(inclusionBlockNumber);
        vm.warp(slasher._getTimestampFromSlot(9994114)); // https://etherscan.io/block/20785012

        // Delegate signs a commitment to include a TX
        TransactionCommitment memory txCommitment =
            _createInclusionCommitment(inclusionBlockNumber, id, committer, committerSecretKey);
        signedCommitment = basicCommitment(committerSecretKey, address(slasher), abi.encode(txCommitment));

        // Build the inclusion proof to prove failure to exclude
        string memory rawPreviousHeader = vm.readFile("./test/testdata/header_20785011.json");
        string memory rawInclusionHeader = vm.readFile("./test/testdata/header_20785012.json");
        string memory ethProof = vm.readFile("./test/testdata/eth_proof_20785011.json");
        string memory txProof = vm.readFile("./test/testdata/tx_mpt_proof_20785012.json");

        bytes[] memory txProofs = new bytes[](1);
        txProofs[0] = _RLPEncodeList(vm.parseJsonBytesArray(txProof, ".proof"));

        uint256[] memory txIndexesInBlock = new uint256[](1);
        txIndexesInBlock[0] = vm.parseJsonUint(txProof, ".index");

        inclusionProof = PreconfStructs.InclusionProof({
            inclusionBlockNumber: inclusionBlockNumber,
            previousBlockHeaderRLP: vm.parseJsonBytes(rawPreviousHeader, ".result"),
            inclusionBlockHeaderRLP: vm.parseJsonBytes(rawInclusionHeader, ".result"),
            accountMerkleProof: _RLPEncodeList(vm.parseJsonBytesArray(ethProof, ".result.accountProof")),
            txMerkleProofs: txProofs,
            txIndexesInBlock: txIndexesInBlock
        });

        // check that the inclusion block transactions root matches the root in the tx proof data.
        bytes32 inclusionTxRoot = slasher._decodeBlockHeaderRLP(inclusionProof.inclusionBlockHeaderRLP).txRoot;
        assertEq(inclusionTxRoot, vm.parseJsonBytes32(txProof, ".root"));
    }

    function test_challenge() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            PreconfStructs.InclusionProof memory inclusionProof
        ) = setupSlash(1);

        bytes32 challengeID =
            slasher.createChallenge{ value: slasher.CHALLENGE_BOND() }(signedCommitment, result.signedDelegation);
        assertEq(challengeID, keccak256(abi.encode(signedCommitment.commitment, result.signedDelegation.delegation)));
    }

    function test_revert_challenge_incorrectBond() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            PreconfStructs.InclusionProof memory inclusionProof
        ) = setupSlash(1);

        uint256 bond = slasher.CHALLENGE_BOND() - 1;
        // Try with incorrect bond amount
        vm.expectRevert(PreconfStructs.IncorrectChallengeBond.selector);
        slasher.createChallenge{ value: bond }(signedCommitment, result.signedDelegation);
    }

    function test_revert_challenge_alreadyExists() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            PreconfStructs.InclusionProof memory inclusionProof
        ) = setupSlash(1);

        uint256 bond = slasher.CHALLENGE_BOND();
        // Create first challenge
        slasher.createChallenge{ value: bond }(signedCommitment, result.signedDelegation);

        // Try to create duplicate challenge
        vm.expectRevert(PreconfStructs.ChallengeAlreadyExists.selector);
        slasher.createChallenge{ value: bond }(signedCommitment, result.signedDelegation);
    }

    function test_revert_challenge_expiredDelegation() public {
        uint256 inclusionBlockNumber = 20_785_012;
        (address alice,) = makeAddrAndKey("alice_expired");
        (address delegate, uint256 delegatePK) = makeAddrAndKey("delegate");
        vm.deal(alice, 100 ether);

        // Set block to before fraud proof window
        vm.roll(inclusionBlockNumber - registry.FRAUD_PROOF_WINDOW());
        vm.warp(inclusionBlockNumber - registry.FRAUD_PROOF_WINDOW() * 12);

        // Register with a soon-to-expire delegation
        bytes memory metadata = abi.encode(delegate);
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: alice,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(slasher),
            metadata: metadata,
            slot: 0 // already expired
         });
        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Create commitment for expired delegation
        vm.roll(inclusionBlockNumber);
        vm.warp(slasher._getTimestampFromSlot(9994114)); // https://etherscan.io/block/20785012
        TransactionCommitment memory commitment =
            _createInclusionCommitment(inclusionBlockNumber, 1, delegate, delegatePK);

        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(committerSecretKey, address(slasher), abi.encode(commitment));

        // Try to create challenge with expired delegation
        uint256 bond = slasher.CHALLENGE_BOND();
        vm.expectRevert(PreconfStructs.DelegationExpired.selector);
        slasher.createChallenge{ value: bond }(signedCommitment, result.signedDelegation);
    }

    function test_slash() public {
        // Register at URC and generate slashable evidence
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            PreconfStructs.InclusionProof memory inclusionProof
        ) = setupSlash(1);

        // Save initial balances for comparison
        uint256 challengerBalanceBefore = challenger.balance;
        uint256 operatorBalanceBefore = operator.balance;
        uint256 urcBalanceBefore = address(registry).balance;
        uint256 bond = slasher.CHALLENGE_BOND();

        // Create challenge
        vm.prank(challenger);
        bytes32 challengeID = slasher.createChallenge{ value: bond }(signedCommitment, result.signedDelegation);

        // Verify challenger's balance decreased by bond amount
        assertEq(challenger.balance, challengerBalanceBefore - bond);

        // Skip ahead past the challenge window
        vm.warp(block.timestamp + slasher.CHALLENGE_WINDOW() + 1);

        // Merkle proof for URC registration
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        bytes32[] memory registrationProof = MerkleTree.generateProof(
            leaves,
            0 // leaf index
        );

        // Slash via URC
        vm.prank(challenger);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[0].signature,
            registrationProof,
            0, // leaf index
            result.signedDelegation,
            signedCommitment,
            abi.encode(inclusionProof)
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

    function test_revert_slash_wrongChallenger() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            PreconfStructs.InclusionProof memory inclusionProof
        ) = setupSlash(1);

        // Create challenge as the original challenger
        vm.prank(challenger);
        bytes32 challengeID =
            slasher.createChallenge{ value: slasher.CHALLENGE_BOND() }(signedCommitment, result.signedDelegation);

        // Skip ahead past the challenge window
        vm.warp(block.timestamp + slasher.CHALLENGE_WINDOW() + 1);

        // Merkle proof for URC registration
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory registrationProof = MerkleTree.generateProof(leaves, leafIndex);

        // Try to slash as different address (not the original challenger)
        vm.prank(operator);
        vm.expectRevert(PreconfStructs.WrongChallengerAddress.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[0].signature,
            registrationProof,
            leafIndex,
            result.signedDelegation,
            signedCommitment,
            abi.encode(inclusionProof)
        );
    }

    function test_revert_slash_notURC() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            PreconfStructs.InclusionProof memory inclusionProof
        ) = setupSlash(1);

        // Try to call slash directly (not through URC)
        vm.expectRevert(PreconfStructs.NotURC.selector);
        slasher.slash(
            result.signedDelegation.delegation, signedCommitment.commitment, abi.encode(inclusionProof), address(0)
        );
    }

    function test_proveChallengeFraudulent() public {
        // Register at URC and generate slashable evidence
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            PreconfStructs.InclusionProof memory inclusionProof
        ) = setupSlash(1);

        // Save initial balances for comparison
        uint256 challengerBalanceBefore = challenger.balance;
        uint256 operatorBalanceBefore = operator.balance;
        uint256 bond = slasher.CHALLENGE_BOND();

        // Create challenge
        vm.prank(challenger);
        bytes32 challengeID = slasher.createChallenge{ value: bond }(signedCommitment, result.signedDelegation);

        // Verify challenger's balance decreased by bond amount
        assertEq(challenger.balance, challengerBalanceBefore - bond);

        // Prove the challenge is fraudulent (transaction was actually included)
        vm.prank(operator);
        slasher.proveChallengeFraudulent(result.signedDelegation.delegation, signedCommitment, inclusionProof);

        // Verify challenger lost their bond (transferred to operator)
        assertEq(operator.balance, operatorBalanceBefore + bond);
        assertEq(challenger.balance, challengerBalanceBefore - bond);

        // Verify challenge was deleted
        (address storedChallenger,) = slasher.challenges(challengeID);
        assertEq(storedChallenger, address(0));
    }

    function test_revert_proveChallengeFraudulent_nonexistentChallenge() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            PreconfStructs.InclusionProof memory inclusionProof
        ) = setupSlash(1);

        // Try to prove fraudulent for a challenge that doesn't exist
        vm.expectRevert(PreconfStructs.ChallengeDoesNotExist.selector);
        slasher.proveChallengeFraudulent(result.signedDelegation.delegation, signedCommitment, inclusionProof);
    }

    // =========== Helper functions ===========

    // Helper to create a test inclusion proof with a recent slot, valid for a recent challenge
    function _createInclusionCommitment(uint256 blockNumber, uint256 id, address delegate, uint256 delegatePK)
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
