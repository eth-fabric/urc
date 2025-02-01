// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

// Adapted from https://github.com/chainbound/bolt/tree/unstable/bolt-contracts

interface PreconfStructs {
    error BlockIsNotFinalized();
    error InvalidParentBlockHash();
    error UnexpectedSigner();
    error TransactionExcluded();
    error WrongTransactionHashProof();
    error BlockIsTooOld();
    error InvalidBlockNumber();
    error InvalidBlockHash();
    error BeaconRootNotFound();
    error DelegationExpired();
    error IncorrectChallengeBond();
    error ChallengeAlreadyExists();
    error ChallengeDoesNotExist();
    error EthTransferFailed();
    error WrongChallengerAddress();
    error FraudProofWindowActive();
    error NotURC();
    struct Challenge {
        address challenger;
        uint256 challengeTimestamp;
    }

    struct TransactionCommitment {
        uint64 slot;
        bytes signature;
        bytes signedTx;
    }

    struct TransactionData {
        bytes32 txHash;
        uint256 nonce;
        uint256 gasLimit;
    }

    struct BlockHeaderData {
        bytes32 parentHash;
        bytes32 stateRoot;
        bytes32 txRoot;
        uint256 blockNumber;
        uint256 timestamp;
        uint256 baseFee;
    }

    struct AccountData {
        uint256 nonce;
        uint256 balance;
    }

    struct InclusionProof {
        // block number where the transactions are included
        uint256 inclusionBlockNumber;
        // RLP-encoded block header of the previous block of the inclusion block
        // (for clarity: `previousBlockHeader.number == inclusionBlockNumber - 1`)
        bytes previousBlockHeaderRLP;
        // RLP-encoded block header where the committed transactions are included
        bytes inclusionBlockHeaderRLP;
        // merkle inclusion proof of the account in the state trie of the previous block
        // (checked against the previousBlockHeader.stateRoot)
        bytes accountMerkleProof;
        // merkle inclusion proof of the transactions in the transaction trie of the inclusion block
        // (checked against the inclusionBlockHeader.txRoot). The order of the proofs should match
        // the order of the committed transactions in the challenge: `Challenge.committedTxs`.
        bytes[] txMerkleProofs;
        // indexes of the committed transactions in the block. The order of the indexes should match
        // the order of the committed transactions in the challenge: `Challenge.committedTxs`.
        uint256[] txIndexesInBlock;
    }
}
