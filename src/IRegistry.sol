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
        /// The authorized addresss for the operator
        address owner;
        /// ETH collateral in GWEI
        uint56 collateralGwei;
        /// The block number when registration occurred
        uint32 registeredAt;
        /// The block number when deregistration occurred
        uint32 unregisteredAt;
        /// The number of blocks that must elapse between deregistering and claiming
        uint16 unregistrationDelay;
        /// The block number when slashed from breaking a commitment
        uint32 slashedAt;
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

    /**
     *
     *                                *
     *            EVENTS              *
     *                                *
     *
     */
    /// @notice Emitted when an operator is registered
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param collateral The collateral amount in GWEI
    /// @param unregistrationDelay The delay before the operator can claim collateral after registering
    event OperatorRegistered(bytes32 registrationRoot, uint256 collateral, uint16 unregistrationDelay);

    /// @notice Emitted when a BLS key is registered
    /// @param leafIndex The index of the BLS key in the registration merkle tree
    /// @param reg The registration
    /// @param leaf The leaf hash value of the `Registration`
    event KeyRegistered(uint256 leafIndex, Registration reg, bytes32 leaf);

    /// @notice Emitted when an operator is slashed for a fraudulent registration
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param challenger The address of the challenger
    /// @param withdrawalAddress The withdrawal address of the operator
    /// @param reg The fraudulent registration
    event RegistrationSlashed(
        bytes32 registrationRoot, address challenger, address withdrawalAddress, Registration reg
    );

    /// @notice Emitted when an operator is slashed for breaking a commitment
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param slashAmountGwei The amount of GWEI slashed
    /// @param rewardAmountGwei The amount of GWEI rewarded to the caller
    /// @param pubkey The BLS public key
    event OperatorSlashed(
        bytes32 registrationRoot, uint256 slashAmountGwei, uint256 rewardAmountGwei, BLS.G1Point pubkey
    );

    /// @notice Emitted when an operator is slashed for equivocation
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param rewardAmountGwei The amount of GWEI rewarded to the caller
    /// @param pubkey The BLS public key
    event OperatorEquivocated(bytes32 registrationRoot, uint256 rewardAmountGwei, BLS.G1Point pubkey);

    /// @notice Emitted when an operator is unregistered
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param unregisteredAt The block number when the operator was unregistered
    event OperatorUnregistered(bytes32 registrationRoot, uint32 unregisteredAt);

    /// @notice Emitted when collateral is claimed
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param collateralGwei The amount of GWEI claimed
    event CollateralClaimed(bytes32 registrationRoot, uint256 collateralGwei);

    /// @notice Emitted when collateral is added
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param collateralGwei The amount of GWEI added
    event CollateralAdded(bytes32 registrationRoot, uint256 collateralGwei);

    /// @notice Emitted when an operator is opted into a proposer commitment protocol
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param slasher The address of the Slasher contract
    /// @param committer The address of the key used for commitments
    /// @param optedInAt The block number when the operator opted in
    event OperatorOptedIn(bytes32 registrationRoot, address slasher, address committer, uint64 optedInAt);

    /// @notice Emitted when an operator is opted out of a proposer commitment protocol
    /// @param registrationRoot The merkle root of the registration merkle tree
    /// @param slasher The address of the Slasher contract
    /// @param optedOutAt The block number when the operator opted out
    event OperatorOptedOut(bytes32 registrationRoot, address slasher, uint64 optedOutAt);

    /**
     *
     *                                *
     *            ERRORS              *
     *                                *
     *
     */
    error InsufficientCollateral();
    error UnregistrationDelayTooShort();
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

    function register(Registration[] calldata registrations, address withdrawalAddress, uint16 unregistrationDelay)
        external
        payable
        returns (bytes32 registrationRoot);

    function verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        external
        view
        returns (uint256 collateralGwei);

    function slashRegistration(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external returns (uint256 collateral);

    function unregister(bytes32 registrationRoot) external;

    function claimCollateral(bytes32 registrationRoot) external;

    function addCollateral(bytes32 registrationRoot) external payable;

    function slashCommitment(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegation,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external returns (uint256 slashAmountGwei, uint256 rewardAmountGwei);

    function slashEquivocation(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegationOne,
        ISlasher.SignedDelegation calldata delegationTwo
    ) external;
}
