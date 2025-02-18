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
        /// ETH collateral in GWEI
        uint56 collateralGwei;
        /// The number of keys registered per operator (capped at 255)
        uint8 numKeys;
        /// The block number when registration occurred
        uint32 registeredAt;
        /// The block number when deregistration occurred
        uint32 unregisteredAt;
        /// The block number when slashed from breaking a commitment
        uint32 slashedAt;
        /// Mapping to track opt-in and opt-out status for proposer commitment protocols
        mapping(address slasher => SlasherCommitment) slasherCommitments;
        /// Historical collateral records
        CollateralRecord[] collateralHistory;
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
        uint56 collateralValue;
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
    /// @param collateralGwei The collateral amount in GWEI
    /// @param owner The owner of the operator
    event OperatorRegistered(bytes32 indexed registrationRoot, uint256 collateralGwei, address owner);

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
    /// @param slashAmountGwei The amount of GWEI slashed
    event OperatorSlashed(
        SlashingType slashingType,
        bytes32 indexed registrationRoot,
        address owner,
        address challenger,
        address indexed slasher,
        uint256 slashAmountGwei
    );

    /// @notice Emitted when an operator is unregistered
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param unregisteredAt The block number when the operator was unregistered
    event OperatorUnregistered(bytes32 indexed registrationRoot, uint32 unregisteredAt);

    /// @notice Emitted when collateral is claimed
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param collateralGwei The amount of GWEI claimed
    event CollateralClaimed(bytes32 indexed registrationRoot, uint256 collateralGwei);

    /// @notice Emitted when collateral is added
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param collateralGwei The amount of GWEI added
    event CollateralAdded(bytes32 indexed registrationRoot, uint256 collateralGwei);

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
    ) external returns (uint256 collateral);

    function slashCommitment(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegation,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external returns (uint256 slashAmountGwei);

    function slashCommitmentFromOptIn(
        bytes32 registrationRoot,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external returns (uint256 slashAmountGwei);

    function slashEquivocation(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegationOne,
        ISlasher.SignedDelegation calldata delegationTwo
    ) external returns (uint256 slashAmountGwei);

    function addCollateral(bytes32 registrationRoot) external payable;

    function claimCollateral(bytes32 registrationRoot) external;

    function claimSlashedCollateral(bytes32 registrationRoot) external;

    function verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        external
        view
        returns (uint256 collateralGwei);

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
    ) external view returns (SlasherCommitment memory slasherCommitment, uint256 collateralGwei);
}
