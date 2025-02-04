// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

// Adapted from https://github.com/chainbound/bolt/tree/unstable/bolt-contracts

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {MerkleTrie} from "./lib/trie/MerkleTrie.sol";
import {SecureMerkleTrie} from "./lib/trie/SecureMerkleTrie.sol";
import {MerkleTrie} from "./lib/trie/MerkleTrie.sol";
import {RLPReader} from "./lib/rlp/RLPReader.sol";
import {RLPWriter} from "./lib/rlp/RLPWriter.sol";
import {TransactionDecoder} from "./lib/TransactionDecoder.sol";
import {PreconfStructs} from "./PreconfStructs.sol";
import {ISlasher} from "../src/ISlasher.sol";

contract InclusionPreconfSlasher is ISlasher, PreconfStructs {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using TransactionDecoder for bytes;
    using TransactionDecoder for TransactionDecoder.Transaction;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    uint256 public SLASH_AMOUNT_GWEI;
    address public constant BEACON_ROOTS_CONTRACT =
        0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
    uint256 public constant EIP4788_WINDOW = 8191;
    uint256 public constant JUSTIFICATION_DELAY = 32;
    uint256 public constant BLOCKHASH_EVM_LOOKBACK = 256;
    uint256 public constant SLOT_TIME = 12;
    uint256 public ETH2_GENESIS_TIMESTAMP;
    uint256 public constant CHALLENGE_WINDOW = 7200;
    uint256 public constant CHALLENGE_BOND = 1 ether;
    address public urc;
    mapping(bytes32 challengeID => Challenge challenge) public challenges;

    constructor(uint256 _slashAmountGwei, address _urc) {
        SLASH_AMOUNT_GWEI = _slashAmountGwei;
        urc = _urc;

        if (block.chainid == 17000) {
            // Holesky
            ETH2_GENESIS_TIMESTAMP = 1695902400;
        } else if (block.chainid == 1) {
            // Mainnet
            ETH2_GENESIS_TIMESTAMP = 1606824023;
        } else if (block.chainid == 7014190335) {
            // Helder
            ETH2_GENESIS_TIMESTAMP = 1718967660;
        }
    }

    // claim that a transaction was not included in a block
    function createChallenge(
        ISlasher.SignedCommitment calldata commitment,
        ISlasher.SignedDelegation calldata signedDelegation
    ) external payable returns (bytes32 challengeID) {
        // Check that the attached bond amount is correct
        if (msg.value != CHALLENGE_BOND) {
            revert IncorrectChallengeBond();
        }

        // decode the opaque commitment payload
        TransactionCommitment memory txCommitment = abi.decode(commitment.commitment.payload, (TransactionCommitment));

        // compute the challenge ID
        challengeID = keccak256(abi.encode(commitment.commitment, signedDelegation.delegation));

        // check if the challenge already exists
        if (challenges[challengeID].challenger != address(0)) {
            revert ChallengeAlreadyExists();
        }

        // Check if the delegation applies to the slot of the commitment
        if (signedDelegation.delegation.slot != txCommitment.slot) {
            revert DelegationExpired();
        }

        // save the challenge
        challenges[challengeID] = Challenge({
            challenger: msg.sender,
            challengeTimestamp: block.timestamp
        });
    }

    // prove that a transaction was included in a block
    // on success, the caller receives the challenge bond and the challenge is deleted
    function proveChallengeFraudulent(
        ISlasher.Delegation calldata delegation,
        ISlasher.SignedCommitment calldata commitment,
        InclusionProof calldata proof
    ) external {
        // recover the challenge
        bytes32 challengeID = keccak256(abi.encode(commitment.commitment, delegation));
        Challenge memory challenge = challenges[challengeID];

        // check if the challenge exists
        if (challenge.challenger == address(0)) {
            revert ChallengeDoesNotExist();
        }

        TransactionCommitment memory txCommitment = abi.decode(commitment.commitment.payload, (TransactionCommitment));

        // If the inclusion proof is valid (doesn't revert) it means the challenge is fraudulent
        _verifyInclusionProof(txCommitment, proof, delegation.committer);

        // Delete the challenge
        delete challenges[challengeID];

        // Transfer the challenge bond to the challenger
        (bool success, ) = msg.sender.call{value: CHALLENGE_BOND}("");
        if (!success) {
            revert EthTransferFailed();
        }
    }

    // slash the operator for not including the transaction. Succeeds if the fraud proof window has expired (meaning no one proved the challenge was fraudulent by proving inclusion).
    // expected to be called by the URC
    // fails if the fraud proof window is active
    // returns the slash amount to the URC and returns the challenge bond to the challenger
    // delegation message does not need to be checked since the challenge() and proveChallengeFraudulent() functions already cover
    function slash(
        ISlasher.Delegation calldata delegation,
        ISlasher.Commitment calldata commitment,
        bytes calldata evidence,
        address challenger
    ) external returns (uint256 slashAmountGwei) {
        if (msg.sender != urc) {
            revert NotURC();
        }

        // recover the challenge ID from the commitment
        bytes32 challengeID = keccak256(abi.encode(commitment, delegation));

        // It is assumed that this is function is called from the URC.slashCommitment() function. This check ensures that only the msg.sender that originates the chain of calls is able to slash the operator
        if (challenges[challengeID].challenger != challenger) {
            revert WrongChallengerAddress();
        }

        // verify the fraud proof window has expired
        if (challenges[challengeID].challengeTimestamp + CHALLENGE_WINDOW > block.timestamp) {
            revert FraudProofWindowActive();
        }

        // delete the challenge
        delete challenges[challengeID];

        // return the challenge bond to the challenger
        (bool success, ) = challenger.call{value: CHALLENGE_BOND}("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Return the slash amount to the URC slasher
        slashAmountGwei = SLASH_AMOUNT_GWEI;
    }

    function slashFromOptIn(
        ISlasher.Commitment calldata commitment,
        bytes calldata evidence,
        address challenger
    ) external returns (uint256 slashAmountGwei) {
        // unused in this example
    }

    function _verifyInclusionProof(
        TransactionCommitment memory commitment,
        InclusionProof memory proof,
        address commitmentSigner
    ) internal view {
        uint256 targetSlot = commitment.slot;
        if (targetSlot > _getCurrentSlot() - JUSTIFICATION_DELAY) {
            // We cannot open challenges for slots that are not finalized by Ethereum consensus yet.
            // This is admittedly a bit strict, since 32-slot deep reorgs are very unlikely.
            revert BlockIsNotFinalized();
        }

        // The visibility of the BLOCKHASH opcode is limited to the 256 most recent blocks.
        // For simplicity we restrict this to 256 slots even though 256 blocks would be more accurate.
        if (targetSlot < _getCurrentSlot() - BLOCKHASH_EVM_LOOKBACK) {
            revert BlockIsTooOld();
        }

        // Check that the previous block is within the EVM lookback window for block hashes.
        // Clearly, if the previous block is available, the target block will be too.
        uint256 previousBlockNumber = proof.inclusionBlockNumber - 1;
        if (
            previousBlockNumber > block.number ||
            previousBlockNumber < block.number - BLOCKHASH_EVM_LOOKBACK
        ) {
            revert InvalidBlockNumber();
        }

        // Get the trusted block hash for the block number in which the transactions were included.
        bytes32 trustedPreviousBlockHash = blockhash(
            proof.inclusionBlockNumber - 1
        );

        // Check the integrity of the trusted block hash
        bytes32 previousBlockHash = keccak256(proof.previousBlockHeaderRLP);
        if (previousBlockHash != trustedPreviousBlockHash) {
            revert InvalidBlockHash();
        }

        // Recover the commitment data if the committed signedTx is valid
        (
            ,
            address recoveredCommitmentSigner,
            TransactionData memory committedTx
        ) = _recoverCommitmentData(commitment);

        // check that the commitment was signed by the expected signer
        if (commitmentSigner != recoveredCommitmentSigner) {
            revert UnexpectedSigner();
        }

        // Decode the RLP-encoded block header of the target block.
        //
        // The target block is necessary to extract the transaction root and verify the inclusion of the
        // committed transaction. By checking against the previous block's parent hash we can ensure this
        // is the correct block trusting a single block hash.
        BlockHeaderData memory targetBlockHeader = _decodeBlockHeaderRLP(
            proof.inclusionBlockHeaderRLP
        );

        // Check that the target block is a child of the previous block
        if (targetBlockHeader.parentHash != previousBlockHash) {
            revert InvalidParentBlockHash();
        }

        // The key in the transaction trie is the RLP-encoded index of the transaction in the block
        bytes memory txLeaf = RLPWriter.writeUint(proof.txIndexesInBlock[0]);

        // Verify transaction inclusion proof
        //
        // The transactions trie is built with raw leaves, without hashing them first
        // (This denotes why we use `MerkleTrie.get()` as opposed to `SecureMerkleTrie.get()`).
        (bool txExists, bytes memory txRLP) = MerkleTrie.get(
            txLeaf,
            proof.txMerkleProofs[0],
            targetBlockHeader.txRoot
        );

        // Not valid to slash them since the transaction doesn't exist according to the proof
        if (!txExists) {
            revert TransactionExcluded();
        }

        // Check if the committed transaction hash matches the hash of the included transaction
        if (committedTx.txHash != keccak256(txRLP)) {
            revert WrongTransactionHashProof();
        }
    }

    /// @notice Recover the commitment data from a signed commitment.
    /// @param commitment The signed commitment to recover the data from.
    /// @return txSender The sender of the committed transaction.
    /// @return commitmentSigner The signer of the commitment.
    /// @return transactionData The decoded transaction data of the committed transaction.
    function _recoverCommitmentData(
        TransactionCommitment memory commitment
    )
        internal
        pure
        returns (
            address txSender,
            address commitmentSigner,
            TransactionData memory transactionData
        )
    {
        commitmentSigner = ECDSA.recover(
            _computeCommitmentID(commitment),
            commitment.signature
        );
        TransactionDecoder.Transaction memory decodedTx = commitment
            .signedTx
            .decodeEnveloped();
        txSender = decodedTx.recoverSender();
        transactionData = TransactionData({
            txHash: keccak256(commitment.signedTx),
            nonce: decodedTx.nonce,
            gasLimit: decodedTx.gasLimit
        });
    }
    /// @notice Compute the commitment ID for a given signed commitment.
    /// @param commitment The signed commitment to compute the ID for.
    /// @return commitmentID The computed commitment ID.
    function _computeCommitmentID(
        TransactionCommitment memory commitment
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    keccak256(commitment.signedTx),
                    _toLittleEndian(commitment.slot)
                )
            );
    }

    /// @notice Helper to convert a u64 to a little-endian bytes
    /// @param x The u64 to convert
    /// @return b The little-endian bytes
    function _toLittleEndian(uint64 x) internal pure returns (bytes memory) {
        bytes memory b = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            b[i] = bytes1(uint8(x >> (8 * i)));
        }
        return b;
    }

    /// @notice Decode the block header fields from an RLP-encoded block header.
    /// @param headerRLP The RLP-encoded block header to decode
    function _decodeBlockHeaderRLP(
        bytes memory headerRLP
    ) public pure returns (BlockHeaderData memory blockHeader) {
        RLPReader.RLPItem[] memory headerFields = headerRLP
            .toRLPItem()
            .readList();

        blockHeader.parentHash = headerFields[0].readBytes32();
        blockHeader.stateRoot = headerFields[3].readBytes32();
        blockHeader.txRoot = headerFields[4].readBytes32();
        blockHeader.blockNumber = headerFields[8].readUint256();
        blockHeader.timestamp = headerFields[11].readUint256();
        blockHeader.baseFee = headerFields[15].readUint256();
    }

    /// @notice Get the slot number from a given timestamp
    /// @param _timestamp The timestamp
    /// @return The slot number
    function _getSlotFromTimestamp(
        uint256 _timestamp
    ) public view returns (uint256) {
        return (_timestamp - ETH2_GENESIS_TIMESTAMP) / SLOT_TIME;
    }

    /// @notice Get the timestamp from a given slot
    /// @param _slot The slot number
    /// @return The timestamp
    function _getTimestampFromSlot(
        uint256 _slot
    ) public view returns (uint256) {
        return ETH2_GENESIS_TIMESTAMP + _slot * SLOT_TIME;
    }

    /// @notice Get the beacon block root for a given slot
    /// @param _slot The slot number
    /// @return The beacon block root
    function _getBeaconBlockRootAtSlot(
        uint256 _slot
    ) internal view returns (bytes32) {
        uint256 slotTimestamp = ETH2_GENESIS_TIMESTAMP + _slot * SLOT_TIME;
        return _getBeaconBlockRootAtTimestamp(slotTimestamp);
    }

    function _getBeaconBlockRootAtTimestamp(
        uint256 _timestamp
    ) internal view returns (bytes32) {
        (bool success, bytes memory data) = BEACON_ROOTS_CONTRACT.staticcall(
            abi.encode(_timestamp)
        );

        if (!success || data.length == 0) {
            revert BeaconRootNotFound();
        }

        return abi.decode(data, (bytes32));
    }

    /// @notice Get the latest beacon block root
    /// @return The beacon block root
    function _getLatestBeaconBlockRoot() internal view returns (bytes32) {
        uint256 latestSlot = _getSlotFromTimestamp(block.timestamp);
        return _getBeaconBlockRootAtSlot(latestSlot);
    }

    /// @notice Get the current slot
    /// @return The current slot
    function _getCurrentSlot() public view returns (uint256) {
        return _getSlotFromTimestamp(block.timestamp);
    }

    /// @notice Check if a timestamp is within the EIP-4788 window
    /// @param _timestamp The timestamp
    /// @return True if the timestamp is within the EIP-4788 window, false otherwise
    function _isWithinEIP4788Window(
        uint256 _timestamp
    ) internal view returns (bool) {
        return
            _getSlotFromTimestamp(_timestamp) <=
            _getCurrentSlot() + EIP4788_WINDOW;
    }
}
