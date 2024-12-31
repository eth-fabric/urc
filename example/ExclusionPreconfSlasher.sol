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

contract ExclusionPreconfSlasher is ISlasher {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using TransactionDecoder for bytes;
    using TransactionDecoder for TransactionDecoder.Transaction;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    uint256 public SLASH_AMOUNT_GWEI;
    uint256 public REWARD_AMOUNT_GWEI;
    address public constant BEACON_ROOTS_CONTRACT =
        0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
    uint256 public constant EIP4788_WINDOW = 8191;
    uint256 public constant JUSTIFICATION_DELAY = 32;
    uint256 public constant BLOCKHASH_EVM_LOOKBACK = 256;
    uint256 public constant SLOT_TIME = 12;
    uint256 public ETH2_GENESIS_TIMESTAMP;

    error BlockIsNotFinalized();
    error InvalidParentBlockHash();
    error UnexpectedSigner();
    error TransactionExcluded();
    error WrongTransactionHashProof();
    error BlockIsTooOld();
    error InvalidBlockNumber();
    error InvalidBlockHash();
    error BeaconRootNotFound();

    constructor(uint256 _slashAmountGwei, uint256 _rewardAmountGwei) {
        SLASH_AMOUNT_GWEI = _slashAmountGwei;
        REWARD_AMOUNT_GWEI = _rewardAmountGwei;

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

    function slash(
        ISlasher.Delegation calldata delegation,
        bytes calldata evidence
    ) external returns (uint256 slashAmountGwei, uint256 rewardAmountGwei) {
        // Operator delegated to an ECDSA signer as part of the metadata field
        address commitmentSigner = abi.decode(delegation.metadata, (address));

        // Recover the slashing evidence
        // commitment: signature to EXCLUDE a tx
        // proof: MPT inclusion proof
        (
            PreconfStructs.SignedCommitment memory commitment,
            PreconfStructs.InclusionProof memory proof
        ) = abi.decode(
                evidence,
                (PreconfStructs.SignedCommitment, PreconfStructs.InclusionProof)
            );

        // If the inclusion proof is valid (doesn't revert) they should be slashed for not excluding the transaction
        _verifyInclusionProof(commitment, proof, commitmentSigner);

        // Return the slash amount to the URC slasher
        slashAmountGwei = SLASH_AMOUNT_GWEI;
        rewardAmountGwei = REWARD_AMOUNT_GWEI;
    }

    function DOMAIN_SEPARATOR() external view returns (bytes memory) {
        return "0xeeeeeeee";
    }

    function _verifyInclusionProof(
        PreconfStructs.SignedCommitment memory commitment,
        PreconfStructs.InclusionProof memory proof,
        address commitmentSigner
    ) internal {
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
            PreconfStructs.TransactionData memory committedTx
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
        PreconfStructs.BlockHeaderData
            memory targetBlockHeader = _decodeBlockHeaderRLP(
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
        PreconfStructs.SignedCommitment memory commitment
    )
        internal
        pure
        returns (
            address txSender,
            address commitmentSigner,
            PreconfStructs.TransactionData memory transactionData
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
        transactionData = PreconfStructs.TransactionData({
            txHash: keccak256(commitment.signedTx),
            nonce: decodedTx.nonce,
            gasLimit: decodedTx.gasLimit
        });
    }
    /// @notice Compute the commitment ID for a given signed commitment.
    /// @param commitment The signed commitment to compute the ID for.
    /// @return commitmentID The computed commitment ID.
    function _computeCommitmentID(
        PreconfStructs.SignedCommitment memory commitment
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
    ) public pure returns (PreconfStructs.BlockHeaderData memory blockHeader) {
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
