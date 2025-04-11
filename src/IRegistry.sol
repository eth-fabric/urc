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

    /// @notice A struct to track the configuration of the registry
    struct Config {
        /// The minimum collateral required to register
        uint80 minCollateralWei;
        /// The fraud proof window
        uint32 fraudProofWindow;
        /// The unregistration delay
        uint32 unregistrationDelay;
        /// The slash window
        uint32 slashWindow;
        /// The opt-in delay
        uint32 optInDelay;
    }

    /// @notice A registration of a BLS key
    struct SignedRegistration {
        /// BLS public key
        BLS.G1Point pubkey;
        /// BLS signature
        BLS.G2Point signature;
    }

    /// @notice Data about an operator
    /// @dev Since mappings cannot be returned from a contract, this struct is used to return operator data
    struct OperatorData {
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
    }

    /// @notice An operator of BLS key[s]
    struct Operator {
        /// The data about the operator
        OperatorData data;
        /// Mapping to track opt-in and opt-out status for proposer commitment protocols
        mapping(address slasher => SlasherCommitment) slasherCommitments;
        /// Historical collateral records
        CollateralRecord[] collateralHistory;
    }

    /// @notice A struct to track opt-in and opt-out status for proposer commitment protocols
    struct SlasherCommitment {
        /// The address of the key used for commitments
        address committer;
        /// The block number when the operator opted in
        uint48 optedInAt;
        /// The block number when the operator opted out
        uint48 optedOutAt;
        /// Whether they have been slashed or not
        bool slashed;
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

    struct RegistrationProof {
        /// The merkle root of the registration merkle tree
        bytes32 registrationRoot;
        /// The registration to verify
        SignedRegistration registration;
        /// The merkle proof to verify the operator's key is in the registry
        bytes32[] merkleProof;
        /// The index of the leaf in the merkle tree
        uint256 leafIndex;
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

    /// @notice Emitted when an operator is unregistered
    /// @param registrationRoot The merkle root of the registration merkle tree
    event OperatorUnregistered(bytes32 indexed registrationRoot);

    /// @notice Emitted when collateral is claimed
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param collateralWei The amount of WEI claimed
    event CollateralClaimed(bytes32 indexed registrationRoot, uint256 collateralWei);

    /// @notice Emitted when collateral is added
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param collateralWei The amount of WEI added
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
    error InvalidProof();
    error NoCollateral();
    error CollateralBelowMinimum();

    /**
     *
     *                                *
     *            FUNCTIONS           *
     *                                *
     *
     */
    function register(SignedRegistration[] calldata registrations, address owner)
        external
        payable
        returns (bytes32 registrationRoot);

    function unregister(bytes32 registrationRoot) external;

    function optInToSlasher(bytes32 registrationRoot, address slasher, address committer) external;

    function optOutOfSlasher(bytes32 registrationRoot, address slasher) external;

    function slashRegistration(RegistrationProof calldata proof) external returns (uint256 collateralWei);

    function slashCommitment(
        RegistrationProof calldata proof,
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
        RegistrationProof calldata proof,
        ISlasher.SignedDelegation calldata delegationOne,
        ISlasher.SignedDelegation calldata delegationTwo
    ) external returns (uint256 slashAmountWei);

    function addCollateral(bytes32 registrationRoot) external payable;

    function claimCollateral(bytes32 registrationRoot) external;

    function claimSlashedCollateral(bytes32 registrationRoot) external;

    // =========== getter functions ===========

    function verifyMerkleProof(RegistrationProof calldata proof) external view;

    function getSlasherCommitment(bytes32 registrationRoot, address slasher)
        external
        view
        returns (SlasherCommitment memory);

    function isOptedIntoSlasher(bytes32 registrationRoot, address slasher) external view returns (bool);

    function getVerifiedOperatorData(RegistrationProof calldata proof) external view returns (OperatorData memory);

    function getHistoricalCollateral(bytes32 registrationRoot, uint256 timestamp)
        external
        view
        returns (uint256 collateralWei);

    function getConfig() external view returns (Config memory config);

    function getOperatorData(bytes32 registrationRoot) external view returns (OperatorData memory operatorData);

    function slashingEvidenceAlreadyUsed(bytes32 slashingDigest) external view returns (bool);

    function getRegistrationProof(SignedRegistration[] calldata regs, address owner, uint256 leafIndex)
        external
        pure
        returns (RegistrationProof memory proof);
}
