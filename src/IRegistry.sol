// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "./lib/BLS.sol";
import { ISlasher } from "./ISlasher.sol";

interface IRegistry {
    /**
     *
     *                                *
     *            STRUCTS             *
     *                                *
     *
     */

    /// @notice A registration of a BLS key
    struct Registration {
        /// BLS public key
        BLS.G1Point pubkey;
        /// BLS signature
        BLS.G2Point signature;
    }

    /// @notice An operator of BLS key[s]
    struct Operator {
        /// The authorized address of the operator
        address owner;
        /// ETH collateral in WEI
        uint80 collateralWei;
        /// The number of keys registered per operator
        uint16 numKeys;
        /// The block number when registration occurred
        uint48 registeredAt;
        /// The block number when deregistration occurred
        uint48 unregisteredAt;
        /// The block number when slashed from breaking a commitment
        uint48 slashedAt;
        /// A field to simulate deletion of the operator, since deleting a struct with a nested mapping is not safe
        bool deleted;
        /// Whether the operator has equivocated or not
        bool equivocated;
        /// Mapping to track opt-in and opt-out status for proposer commitment protocols
        mapping(address slasher => SlasherCommitment) slasherCommitments;
        /// Historical collateral records
        CollateralRecord[] collateralHistory;
    }

    struct PendingSlash {
        SlashingType slashType;
        uint32 reportedAt;
        uint32 canExecuteAt;
        address reporter;
        uint256 slashAmountWei;
        bytes32 slashingDigest;
        bytes32 reversedSlashingDigest;
        uint64 slotId;
    }

    /// @notice A struct to track opt-in and opt-out status for proposer commitment protocols
    struct SlasherCommitment {
        /// The block number when the operator opted in
        uint64 optedInAt;
        /// The block number when the operator opted out
        uint64 optedOutAt;
        /// The address of the key used for commitments
        address committer;
    }

    /// @notice A record of collateral at a specific timestamp
    struct CollateralRecord {
        uint64 timestamp;
        uint80 collateralValue;
    }

    enum SlashingType {
        Fraud,
        Equivocation,
        Commitment
    }

    /**
     *
     *                                *
     *            EVENTS              *
     *                                *
     *
     */
    /// @notice Emitted when an operator is registered
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param collateralWei The collateral amount in WEI
    /// @param owner The owner of the operator
    event OperatorRegistered(bytes32 indexed registrationRoot, uint256 collateralWei, address owner);

    /// @notice Emitted when a BLS key is registered
    /// @param leafIndex The index of the BLS key in the registration merkle tree
    /// @param reg The registration
    /// @param leaf The leaf hash value of the `Registration`
    event KeyRegistered(uint256 leafIndex, Registration reg, bytes32 leaf);


    /// @notice Emitted when an operator is slashed for fraud, equivocation, or breaking a commitment
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param owner The owner of the operator
    /// @param challenger The address of the challenger
    /// @param slashingType The type of slashing
    /// @param slasher The address of the slasher
    /// @param slashAmountWei The amount of WEI slashed
    event OperatorSlashed(
        SlashingType slashingType,
        bytes32 indexed registrationRoot,
        address owner,
        address challenger,
        address indexed slasher,
        uint256 slashAmountWei
    );

    /// @notice Emitted when a slash event is queued
    /// @param registrationRoot
    /// @param slashType
    /// @param slashAmount
    event SlashQueued(bytes32 registrationRoot, SlashingType slashType, uint256 slashAmount);

    /// @notice Emitted when an operator is unregistered
    /// @param registrationRoot The merkle root of the registration merkle tree
    event OperatorUnregistered(bytes32 indexed registrationRoot);

    /// @notice Emitted when collateral is claimed
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param collateralWei The amount of Wei claimed
    event CollateralClaimed(bytes32 indexed registrationRoot, uint256 collateralWei);

    /// @notice Emitted when collateral is added
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param collateralWei The amount of Wei added
    event CollateralAdded(bytes32 indexed registrationRoot, uint256 collateralWei);

    /// @notice Emitted when an operator is opted into a proposer commitment protocol
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param slasher The address of the Slasher contract
    /// @param committer The address of the key used for commitments
    event OperatorOptedIn(bytes32 indexed registrationRoot, address indexed slasher, address indexed committer);

    /// @notice Emitted when an operator is opted out of a proposer commitment protocol
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param slasher The address of the Slasher contract
    event OperatorOptedOut(bytes32 indexed registrationRoot, address indexed slasher);

    /**
     *
     *                                *
     *            ERRORS              *
     *                                *
     *
     */
    error OperatorDeleted();
    error TimestampTooOld();
    error SlotAlreadySlashed();
    error DustAmountNotAllowed();
    error NoSlashPending();
    error SlashWaitingPeriodNotMet();
    error InsufficientCollateral();
    error OperatorAlreadyRegistered();
    error OperatorDeleted();
    error InvalidRegistrationRoot();
    error EthTransferFailed();
    error WrongOperator();
    error AlreadyUnregistered();
    error NotUnregistered();
    error UnregistrationDelayNotMet();
    error NoCollateralToClaim();
    error FraudProofWindowExpired();
    error FraudProofWindowNotMet();
    error DelegationSignatureInvalid();
    error SlashAmountExceedsCollateral();
    error NoCollateralSlashed();
    error NotRegisteredKey();
    error FraudProofMerklePathInvalid();
    error FraudProofChallengeInvalid();
    error CollateralOverflow();
    error OperatorAlreadyUnregistered();
    error SlashWindowExpired();
    error SlashingAlreadyOccurred();
    error NotSlashed();
    error SlashWindowNotMet();
    error UnauthorizedCommitment();
    error InvalidDelegation();
    error DifferentSlots();
    error DelegationsAreSame();
    error OperatorAlreadyEquivocated();
    error TimestampTooOld();
    error AlreadyOptedIn();
    error NotOptedIn();
    error OptInDelayNotMet();

    /**
     *
     *                                *
     *            FUNCTIONS           *
     *                                *
     *
     */
    function register(Registration[] calldata registrations, address owner)
        external
        payable
        returns (bytes32 registrationRoot);

    function unregister(bytes32 registrationRoot) external;

    function optInToSlasher(bytes32 registrationRoot, address slasher, address committer) external;

    function optOutOfSlasher(bytes32 registrationRoot, address slasher) external;

    function slashRegistration(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external returns (uint256 collateralWei);

    function slashCommitment(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegation,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external returns (uint256 slashAmountWei);

    function slashCommitmentFromOptIn(
        bytes32 registrationRoot,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external returns (uint256 slashAmountWei);

    function slashEquivocation(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegationOne,
        ISlasher.SignedDelegation calldata delegationTwo
    ) external returns (uint256 slashAmountWei);

    function addCollateral(bytes32 registrationRoot) external payable;

    function claimCollateral(bytes32 registrationRoot) external;

    function claimSlashedCollateral(bytes32 registrationRoot) external;

    function verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        external
        view
        returns (uint256 collateralWei);

    function getSlasherCommitment(bytes32 registrationRoot, address slasher)
        external
        view
        returns (SlasherCommitment memory slasherCommitment);

    function isOptedIntoSlasher(bytes32 registrationRoot, address slasher) external view returns (bool);

    function getOptedInCommitter(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex,
        address slasher
    ) external view returns (SlasherCommitment memory slasherCommitment, uint256 collateralWei);
}
