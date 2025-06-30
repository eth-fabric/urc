// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { BLS } from "./lib/BLS.sol";
import { MerkleTree } from "./lib/MerkleTree.sol";
import { IRegistry } from "./IRegistry.sol";
import { ISlasher } from "./ISlasher.sol";

contract Registry is IRegistry {
    using BLS for *;

    /// @notice Mapping from registration merkle roots to Operator structs
    mapping(bytes32 registrationRoot => Operator) private operators;

    /// @notice Mapping to track if a slashing has occurred before with same input
    mapping(bytes32 slashingDigest => bool) private slashedBefore;

    // Constants
    address internal constant BURNER_ADDRESS = address(0x0000000000000000000000000000000000000000);
    bytes public constant REGISTRATION_DOMAIN_SEPARATOR = "0x00555243"; // "URC" in little endian
    bytes public constant DELEGATION_DOMAIN_SEPARATOR = "0x0044656c"; // "Del" in little endian

    /// @notice The configuration for the URC
    Config private config;

    constructor(Config memory _config) {
        config = _config;
    }

    /**
     *
     *                                Registration/Unregistration Functions                           *
     *
     */

    /// @inheritdoc IRegistry
    function register(SignedRegistration[] calldata registrations, address owner)
        external
        payable
        returns (bytes32 registrationRoot)
    {
        // At least minCollateralWei required to sufficiently reward fraud/equivocation challenges
        if (msg.value < config.minCollateralWei) {
            revert InsufficientCollateral();
        }

        // Prevent overflow of collateral
        if (msg.value > type(uint80).max) revert CollateralOverflow();

        // Prevent 0 address as owner
        if (owner == address(0)) revert InvalidOwnerAddress();

        // note: owner address is mixed into the Merkle leaves to bind the registrationRoot to the owner
        registrationRoot = _merkleizeSignedRegistrationsWithOwner(registrations, owner);

        // Revert on a bad registration root
        if (registrationRoot == bytes32(0)) revert InvalidRegistrationRoot();

        // Prevent reusing a deleted operator
        if (operators[registrationRoot].data.deleted) revert OperatorDeleted();

        // Prevent duplicates from overwriting previous registrations
        if (operators[registrationRoot].data.registeredAt != 0) {
            revert OperatorAlreadyRegistered();
        }

        // Each Operator is mapped to a unique registration root
        Operator storage newOperator = operators[registrationRoot];
        newOperator.data.owner = owner;
        newOperator.data.collateralWei = uint80(msg.value);
        newOperator.data.numKeys = uint16(registrations.length);
        newOperator.data.registeredAt = uint48(block.timestamp);
        newOperator.data.unregisteredAt = type(uint48).max;
        newOperator.data.slashedAt = 0;

        // Store the initial collateral value in the history
        newOperator.collateralHistory.push(
            CollateralRecord({ timestamp: uint64(block.timestamp), collateralValue: uint80(msg.value) })
        );

        emit OperatorRegistered(registrationRoot, msg.value, owner);
    }

    /// @inheritdoc IRegistry
    function unregister(bytes32 registrationRoot) external {
        Operator storage operator = operators[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) revert OperatorDeleted();

        // Only the authorized owner can unregister
        if (operator.data.owner != msg.sender) revert WrongOperator();

        // Prevent double unregistrations
        if (operator.data.unregisteredAt != type(uint48).max) {
            revert AlreadyUnregistered();
        }

        // Prevent a slashed operator from unregistering
        // They must wait for the slash window to pass before calling claimSlashedCollateral()
        if (operator.data.slashedAt != 0) revert SlashingAlreadyOccurred();

        // Save the block number; they must wait for the unregistration delay to claim collateral
        operator.data.unregisteredAt = uint48(block.timestamp);

        emit OperatorUnregistered(registrationRoot);
    }

    /// @inheritdoc IRegistry
    function optInToSlasher(bytes32 registrationRoot, address slasher, address committer) external {
        Operator storage operator = operators[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) revert OperatorDeleted();

        // Only the authorized owner can opt in
        if (operator.data.owner != msg.sender) revert WrongOperator();

        // Operator cannot opt in before the fraud proof window elapses
        if (block.timestamp < operator.data.registeredAt + config.fraudProofWindow) {
            revert FraudProofWindowNotMet();
        }

        // Retrieve the SlasherCommitment struct
        SlasherCommitment storage slasherCommitment = operator.slasherCommitments[slasher];

        // Check if they've been slashed before
        if (slasherCommitment.slashed || operator.data.slashedAt != 0) {
            revert SlashingAlreadyOccurred();
        }

        // Check if already opted in
        if (slasherCommitment.optedOutAt < slasherCommitment.optedInAt) {
            revert AlreadyOptedIn();
        }

        // If previously opted out, enforce delay before allowing new opt-in
        if (slasherCommitment.optedOutAt != 0 && block.timestamp < slasherCommitment.optedOutAt + config.optInDelay) {
            revert OptInDelayNotMet();
        }

        // Save the block number and committer
        slasherCommitment.optedInAt = uint48(block.timestamp);
        slasherCommitment.optedOutAt = 0;
        slasherCommitment.committer = committer;

        emit OperatorOptedIn(registrationRoot, slasher, committer);
    }

    /// @inheritdoc IRegistry
    function optOutOfSlasher(bytes32 registrationRoot, address slasher) external {
        Operator storage operator = operators[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) revert OperatorDeleted();

        // Only the authorized owner can opt out
        if (operator.data.owner != msg.sender) revert WrongOperator();

        // Retrieve the SlasherCommitment struct
        SlasherCommitment storage slasherCommitment = operator.slasherCommitments[slasher];

        // Check if already opted out or never opted in
        if (slasherCommitment.optedOutAt >= slasherCommitment.optedInAt) {
            revert NotOptedIn();
        }

        // Enforce a delay before allowing opt-out
        if (block.timestamp < slasherCommitment.optedInAt + config.optInDelay) {
            revert OptInDelayNotMet();
        }

        // Save the block number
        slasherCommitment.optedOutAt = uint48(block.timestamp);

        emit OperatorOptedOut(registrationRoot, slasher);
    }

    /**
     *
     *                                Slashing Functions                           *
     *
     */
    modifier isSlashableCommitment(bytes32 registrationRoot) {
        OperatorData memory operator = operators[registrationRoot].data;

        // Prevent reusing a deleted operator
        if (operator.deleted) revert OperatorDeleted();

        // Operator is not liable for slashings before the fraud proof window elapses
        if (block.timestamp < operator.registeredAt + config.fraudProofWindow) {
            revert FraudProofWindowNotMet();
        }

        // Operator is not liable for slashings after unregister and the delay has passed
        if (
            operator.unregisteredAt != type(uint48).max
                && block.timestamp > operator.unregisteredAt + config.unregistrationDelay
        ) {
            revert OperatorAlreadyUnregistered();
        }

        // Slashing can only occur within the slash window after the first reported slashing
        // After the slash window has passed, the operator can claim collateral
        if (operator.slashedAt != 0 && block.timestamp > operator.slashedAt + config.slashWindow) {
            revert SlashWindowExpired();
        }

        _;
    }

    /// @inheritdoc IRegistry
    function slashRegistration(RegistrationProof calldata proof) external returns (uint256 slashedCollateralWei) {
        Operator storage operator = operators[proof.registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) revert OperatorDeleted();

        // Calculate a unique identifier for the slashing evidence
        bytes32 slashingDigest = keccak256(abi.encode(proof));

        // Prevent slashing with same inputs
        if (slashedBefore[slashingDigest]) revert SlashingAlreadyOccurred();

        // Save the slashing digest
        slashedBefore[slashingDigest] = true;

        // Can only slash registrations within the fraud proof window
        if (block.timestamp > operator.data.registeredAt + config.fraudProofWindow) {
            revert FraudProofWindowExpired();
        }

        // 0 collateral implies the registration was not part of the registry or they were previously slashed to 0
        if (operator.data.collateralWei == 0) revert NoCollateral();

        // They must have at least the minimum collateral for _rewardAndBurn
        if (operator.data.collateralWei < config.minCollateralWei) {
            revert CollateralBelowMinimum();
        }

        // Verify the registration is part of the registry
        // It will revert if the registration proof is invalid
        _verifyMerkleProof(proof);

        // Reconstruct registration message
        bytes memory message = abi.encode(operator.data.owner);

        // Verify registration signature, note the domain separator mixin
        if (BLS.verify(message, proof.registration.signature, proof.registration.pubkey, REGISTRATION_DOMAIN_SEPARATOR))
        {
            revert FraudProofChallengeInvalid();
        }

        // Save timestamp only once to start the slash window
        if (operator.data.slashedAt == 0) {
            operator.data.slashedAt = uint48(block.timestamp);
        }

        // Decrement operator's collateral
        operator.data.collateralWei -= uint80(config.minCollateralWei);

        // Burn half of the MIN_COLLATERAL amount and reward the challenger the other half
        _rewardAndBurn(config.minCollateralWei / 2, msg.sender);

        // Push collateral changes
        operator.collateralHistory.push(
            CollateralRecord({ timestamp: uint64(block.timestamp), collateralValue: operator.data.collateralWei })
        );

        emit OperatorSlashed(
            SlashingType.Fraud,
            proof.registrationRoot,
            operator.data.owner,
            msg.sender,
            address(this),
            config.minCollateralWei / 2
        );

        return config.minCollateralWei;
    }

    /// @inheritdoc IRegistry
    function slashCommitment(
        RegistrationProof calldata proof,
        ISlasher.SignedDelegation calldata delegation,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external isSlashableCommitment(proof.registrationRoot) returns (uint256 slashAmountWei) {
        // Calculate a unique identifier for the slashing evidence
        bytes32 slashingDigest =
            keccak256(abi.encode(delegation, commitment, keccak256(evidence), proof.registrationRoot));

        // Prevent slashing with same inputs
        if (slashedBefore[slashingDigest]) revert SlashingAlreadyOccurred();

        // Verify the delegation was signed by the operator's BLS key
        // This is a sanity check to ensure the delegation is valid
        // It will revert if the registration proof is invalid or the Delegation signature is invalid
        _verifyDelegation(proof, delegation);

        // Verify the commitment was signed by the commitment key from the Delegation
        address committer = ECDSA.recover(keccak256(abi.encode(commitment.commitment)), commitment.signature);
        if (committer != delegation.delegation.committer) {
            revert UnauthorizedCommitment();
        }

        // Prevent same slashing from occurring again
        slashedBefore[slashingDigest] = true;

        // Call the Slasher contract to slash the operator
        slashAmountWei = ISlasher(commitment.commitment.slasher).slash(
            delegation.delegation, commitment.commitment, committer, evidence, msg.sender
        );

        // Handle the slashing accounting
        _slashCommitment(proof.registrationRoot, slashAmountWei, commitment.commitment.slasher);
    }

    /// @inheritdoc IRegistry
    function slashCommitment(
        bytes32 registrationRoot,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external isSlashableCommitment(registrationRoot) returns (uint256 slashAmountWei) {
        Operator storage operator = operators[registrationRoot];

        // Recover the SlasherCommitment entry
        SlasherCommitment storage slasherCommitment = operator.slasherCommitments[commitment.commitment.slasher];

        // Verify the operator has opted-in in the past
        if (slasherCommitment.optedInAt == 0) revert NotOptedIn();

        // Prevent slashing if they've opted out and the slash window has passed
        // The slashWindow is to enforce a malicious operator can be slashed immediately after opting out
        if (slasherCommitment.optedOutAt > 0 && block.timestamp >= slasherCommitment.optedOutAt + config.slashWindow) {
            revert SlashWindowExpired();
        }

        // Verify the commitment was signed by the registered committer from the optInToSlasher() function
        address committer = ECDSA.recover(keccak256(abi.encode(commitment.commitment)), commitment.signature);
        if (committer != slasherCommitment.committer) {
            revert UnauthorizedCommitment();
        }

        // Save timestamp only once to start the slash window
        if (operator.data.slashedAt == 0) {
            operator.data.slashedAt = uint48(block.timestamp);
        }

        // Set the operator's SlasherCommitment to slashed
        slasherCommitment.slashed = true;

        // The Slasher interface requires a Delegation struct so we pass in an empty one
        ISlasher.Delegation memory dummyDelegation;

        // Call the Slasher contract to slash the operator
        slashAmountWei = ISlasher(commitment.commitment.slasher).slash(
            dummyDelegation, commitment.commitment, committer, evidence, msg.sender
        );

        // Handle the slashing accounting
        _slashCommitment(registrationRoot, slashAmountWei, commitment.commitment.slasher);
    }

    /// @inheritdoc IRegistry
    function slashEquivocation(
        RegistrationProof calldata proof,
        ISlasher.SignedDelegation calldata delegationOne,
        ISlasher.SignedDelegation calldata delegationTwo
    ) external returns (uint256 slashAmountWei) {
        Operator storage operator = operators[proof.registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) revert OperatorDeleted();

        // Prevent slashing an operator that has already equivocated
        if (operator.data.equivocated) revert OperatorAlreadyEquivocated();

        // Verify the delegations are not identical by comparing only essential fields
        if (
            delegationOne.delegation.slot == delegationTwo.delegation.slot
                && keccak256(abi.encode(delegationOne.delegation.delegate))
                    == keccak256(abi.encode(delegationTwo.delegation.delegate))
                && delegationOne.delegation.committer == delegationTwo.delegation.committer
        ) {
            revert DelegationsAreSame();
        }

        // Operator is not liable for slashings before the fraud proof window elapses
        if (block.timestamp < operator.data.registeredAt + config.fraudProofWindow) {
            revert FraudProofWindowNotMet();
        }

        // Operator is not liable for slashings after unregister and the delay has passed
        if (
            operator.data.unregisteredAt != type(uint48).max
                && block.timestamp > operator.data.unregisteredAt + config.unregistrationDelay
        ) {
            revert OperatorAlreadyUnregistered();
        }

        // Slashing can only occur within the slash window after the first reported slashing
        // After the slash window has passed, the operator can claim collateral
        if (operator.data.slashedAt != 0 && block.timestamp > operator.data.slashedAt + config.slashWindow) {
            revert SlashWindowExpired();
        }

        // Verify both delegations were signed by the operator's BLS key
        // It will revert if either the registration proof is invalid or the Delegation signature is invalid
        _verifyDelegation(proof, delegationOne);
        _verifyDelegation(proof, delegationTwo);

        // Verify the delegations are for the same slot
        if (delegationOne.delegation.slot != delegationTwo.delegation.slot) {
            revert DifferentSlots();
        }

        // Mark the operator as equivocated
        operator.data.equivocated = true;

        // Save timestamp only once to start the slash window
        if (operator.data.slashedAt == 0) {
            operator.data.slashedAt = uint48(block.timestamp);
        }

        // Decrement operator's collateral
        operator.data.collateralWei -= uint80(config.minCollateralWei);

        // Push collateral changes
        operator.collateralHistory.push(
            CollateralRecord({ timestamp: uint64(block.timestamp), collateralValue: operator.data.collateralWei })
        );

        // Burn half of the MIN_COLLATERAL amount and reward the challenger the other half
        _rewardAndBurn(config.minCollateralWei / 2, msg.sender);

        emit OperatorSlashed(
            SlashingType.Equivocation,
            proof.registrationRoot,
            operator.data.owner,
            msg.sender,
            address(this),
            config.minCollateralWei
        );

        return config.minCollateralWei;
    }

    /**
     *
     *                                Collateral Functions                           *
     *
     */

    /// @inheritdoc IRegistry
    function addCollateral(bytes32 registrationRoot) external payable {
        Operator storage operator = operators[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) revert OperatorDeleted();

        // Zero collateral implies they were previously slashed to 0 or did not exist and must re-register
        if (operator.data.collateralWei == 0) revert NoCollateral();

        // Prevent overflow
        if (msg.value > type(uint80).max) revert CollateralOverflow();

        // Update their collateral amount
        operator.data.collateralWei += uint80(msg.value);

        // Store the updated collateral value in the history
        operator.collateralHistory.push(
            CollateralRecord({ timestamp: uint64(block.timestamp), collateralValue: operator.data.collateralWei })
        );

        emit CollateralAdded(registrationRoot, operator.data.collateralWei);
    }

    /// @inheritdoc IRegistry
    function claimCollateral(bytes32 registrationRoot) external {
        Operator storage operator = operators[registrationRoot];
        address operatorOwner = operator.data.owner;
        uint256 collateralWei = operator.data.collateralWei;

        // Prevent reusing a deleted operator
        if (operator.data.deleted) revert OperatorDeleted();

        // Check that they've unregistered
        if (operator.data.unregisteredAt == type(uint48).max) {
            revert NotUnregistered();
        }

        // Check that enough time has passed
        if (block.timestamp < operator.data.unregisteredAt + config.unregistrationDelay) {
            revert UnregistrationDelayNotMet();
        }

        // Check that the operator has not been slashed
        if (operator.data.slashedAt != 0) revert SlashingAlreadyOccurred();

        // Prevent the Operator from being reused
        operator.data.deleted = true;

        // Transfer to operator
        bool success;
        assembly ("memory-safe") {
            success := call(gas(), operatorOwner, collateralWei, 0, 0, 0, 0)
        }
        if (!success) revert EthTransferFailed();

        emit CollateralClaimed(registrationRoot, collateralWei);
    }

    /// @inheritdoc IRegistry
    function claimSlashedCollateral(bytes32 registrationRoot) external {
        Operator storage operator = operators[registrationRoot];
        address owner = operator.data.owner;
        uint256 collateralWei = operator.data.collateralWei;

        // Prevent reusing a deleted operator
        if (operator.data.deleted) revert OperatorDeleted();

        // Check that they've been slashed
        if (operator.data.slashedAt == 0) revert NotSlashed();

        // Check that enough time has passed
        if (block.timestamp < operator.data.slashedAt + config.slashWindow) {
            revert SlashWindowNotMet();
        }

        // Prevent the Operator from being reused
        operator.data.deleted = true;

        // Transfer collateral to owner
        bool success;
        assembly ("memory-safe") {
            success := call(gas(), owner, collateralWei, 0, 0, 0, 0)
        }

        if (!success) revert EthTransferFailed();

        emit CollateralClaimed(registrationRoot, collateralWei);
    }

    /**
     *
     *                                Getter Functions                           *
     *
     */

    /// @inheritdoc IRegistry
    function getConfig() external view returns (Config memory) {
        return config;
    }

    /// @inheritdoc IRegistry
    function getOperatorData(bytes32 registrationRoot) external view returns (OperatorData memory operatorData) {
        operatorData = operators[registrationRoot].data;
    }

    /// @inheritdoc IRegistry
    function verifyMerkleProof(RegistrationProof calldata proof) external view {
        _verifyMerkleProof(proof);
    }

    /// @inheritdoc IRegistry
    function getSlasherCommitment(bytes32 registrationRoot, address slasher)
        external
        view
        returns (SlasherCommitment memory)
    {
        return operators[registrationRoot].slasherCommitments[slasher];
    }

    /// @inheritdoc IRegistry
    function isSlashed(bytes32 registrationRoot) external view returns (bool slashed) {
        slashed = operators[registrationRoot].data.slashedAt != 0;
    }

    /// @inheritdoc IRegistry
    function isSlashed(bytes32 registrationRoot, address slasher) external view returns (bool slashed) {
        slashed = operators[registrationRoot].slasherCommitments[slasher].slashed;
    }

    /// @inheritdoc IRegistry
    function isOptedIntoSlasher(bytes32 registrationRoot, address slasher) external view returns (bool) {
        SlasherCommitment memory slasherCommitment = operators[registrationRoot].slasherCommitments[slasher];
        return slasherCommitment.optedOutAt < slasherCommitment.optedInAt && !slasherCommitment.slashed;
    }

    /// @inheritdoc IRegistry
    function getVerifiedOperatorData(RegistrationProof calldata proof) external view returns (OperatorData memory) {
        OperatorData memory operatorData = operators[proof.registrationRoot].data;

        // Revert if the proof is invalid
        _verifyMerkleProof(proof);

        return operatorData;
    }

    /// @inheritdoc IRegistry
    function slashingEvidenceAlreadyUsed(bytes32 slashingDigest) external view returns (bool) {
        return slashedBefore[slashingDigest];
    }

    /// @inheritdoc IRegistry
    function getHistoricalCollateral(bytes32 registrationRoot, uint256 timestamp)
        external
        view
        returns (uint256 collateralWei)
    {
        CollateralRecord[] storage records = operators[registrationRoot].collateralHistory;
        if (records.length == 0) {
            return 0;
        }

        // Add timestamp validation
        if (timestamp < records[0].timestamp) {
            revert TimestampTooOld();
        }

        // Binary search for the closest timestamp less than the requested timestamp
        uint256 low = 0;
        uint256 high = records.length - 1;
        uint256 closestCollateralValue = 0;

        while (low <= high) {
            uint256 mid = low + (high - low) / 2;
            if (records[mid].timestamp < timestamp) {
                closestCollateralValue = records[mid].collateralValue;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        return closestCollateralValue;
    }

    /// @inheritdoc IRegistry
    function getRegistrationProof(SignedRegistration[] calldata regs, address owner, uint256 leafIndex)
        external
        pure
        returns (RegistrationProof memory proof)
    {
        proof.registrationRoot = _merkleizeSignedRegistrationsWithOwner(regs, owner);
        proof.registration = regs[leafIndex];

        bytes32[] memory leaves = _hashToLeaves(regs, owner);
        proof.merkleProof = MerkleTree.generateProof(leaves, leafIndex);
    }

    /**
     *
     *                                Helper Functions                           *
     *
     */

    /// @notice Handles the slashing accounting for a commitment
    /// @dev The function will revert if:
    /// @dev - The slash amount exceeds the operator's collateral (SlashAmountExceedsCollateral)
    /// @dev - ETH transfer to burner address fails (EthTransferFailed)
    /// @param registrationRoot The registration root of the operator
    /// @param slashAmountWei The amount of collateral to slash
    /// @param slasher The address of the slasher
    function _slashCommitment(bytes32 registrationRoot, uint256 slashAmountWei, address slasher) internal {
        Operator storage operator = operators[registrationRoot];

        // Save timestamp only once to start the slash window
        if (operator.data.slashedAt == 0) {
            operator.data.slashedAt = uint48(block.timestamp);
        }

        // Prevent slashing if the slashing amount is 0
        if (slashAmountWei == 0) revert NoCollateralSlashed();

        // Prevent slashing more than the operator's collateral
        if (slashAmountWei > operator.data.collateralWei) {
            revert SlashAmountExceedsCollateral();
        }

        // Decrement operator's collateral
        operator.data.collateralWei -= uint80(slashAmountWei);

        // Push collateral changes
        operator.collateralHistory.push(
            CollateralRecord({ timestamp: uint64(block.timestamp), collateralValue: operator.data.collateralWei })
        );

        // Burn the slashed amount
        _burnETH(slashAmountWei);

        emit OperatorSlashed(
            SlashingType.Commitment, registrationRoot, operator.data.owner, msg.sender, slasher, slashAmountWei
        );
    }
    /// @notice Hashes an array of `SignedRegistration` structs with the owner address
    /// @dev Leaves are created by abi-encoding the `SignedRegistration` structs with the owner address, then hashing with keccak256.
    /// @param regs The array of `SignedRegistration` structs to hash
    /// @param owner The owner address of the operator
    /// @return leaves The array of hashed leaves

    function _hashToLeaves(SignedRegistration[] calldata regs, address owner)
        internal
        pure
        returns (bytes32[] memory leaves)
    {
        // Create leaf nodes by hashing SignedRegistration structs
        leaves = new bytes32[](regs.length);
        for (uint256 i = 0; i < regs.length; i++) {
            leaves[i] = keccak256(abi.encode(regs[i], owner));
        }
    }

    /// @notice Merkleizes an array of `SignedRegistration` structs
    /// @dev Leaves are created by abi-encoding the `SignedRegistration` structs with the owner address, then hashing with keccak256.
    /// @param regs The array of `SignedRegistration` structs to merkleize
    /// @return registrationRoot The merkle root of the registration
    function _merkleizeSignedRegistrationsWithOwner(SignedRegistration[] calldata regs, address owner)
        internal
        pure
        returns (bytes32 registrationRoot)
    {
        // Create leaves array with padding
        bytes32[] memory leaves = _hashToLeaves(regs, owner);

        // Merkleize the leaves
        registrationRoot = MerkleTree.generateTree(leaves);
    }

    /// @notice Verifies a merkle proof for a given `RegistrationProof`
    /// @dev The function will revert if the proof is invalid
    /// @dev The function checks against registered operators to get the owner address and
    /// @dev should revert if the proof doesn't correspond to a real registration
    /// @param proof The merkle proof to verify the operator's key is in the registry
    function _verifyMerkleProof(RegistrationProof calldata proof) internal view {
        address owner = operators[proof.registrationRoot].data.owner;
        bytes32 leaf = keccak256(abi.encode(proof.registration, owner));
        if (!MerkleTree.verifyProofCalldata(proof.registrationRoot, leaf, proof.merkleProof)) {
            revert InvalidProof();
        }
    }

    /// @notice Verifies a delegation was signed by an operator's registered BLS key
    /// @dev The function will return revert if either the registration proof is invalid
    /// @dev or the Delegation signature is invalid
    /// @dev The `signedDelegation.signature` is expected to be the abi-encoded `Delegation` message mixed with the URC's `DELEGATION_DOMAIN_SEPARATOR`.
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param delegation The SignedDelegation signed by the operator's BLS key
    function _verifyDelegation(RegistrationProof calldata proof, ISlasher.SignedDelegation calldata delegation)
        internal
        view
    {
        // Verify the public key in the proof is the same as the public key in the SignedDelegation
        if (keccak256(abi.encode(proof.registration.pubkey)) != keccak256(abi.encode(delegation.delegation.proposer))) {
            revert InvalidProof();
        }

        // Verify the registration proof is valid (reverts if invalid)
        _verifyMerkleProof(proof);

        // Reconstruct Delegation message
        bytes memory message = abi.encode(delegation.delegation);

        // Verify it was signed by the registered BLS key
        if (!BLS.verify(message, delegation.signature, delegation.delegation.proposer, DELEGATION_DOMAIN_SEPARATOR)) {
            revert DelegationSignatureInvalid();
        }
    }

    /// @notice Burns ether
    /// @dev The function will revert if the transfer to the BURNER_ADDRESS fails.
    /// @param amountWei The amount of WEI to be burned
    function _burnETH(uint256 amountWei) internal {
        // Burn the slash amount
        bool success;
        address burner = BURNER_ADDRESS;
        assembly ("memory-safe") {
            success := call(gas(), burner, amountWei, 0, 0, 0, 0)
        }
        if (!success) revert EthTransferFailed();
    }

    /// @notice Burns `amountWei` ether and rewards `amountWei` the challenger address
    /// @dev The function will revert if the transfer to the challenger fails.
    /// @dev In total, `2 * amountWei` WEI is leaving the contract
    /// @param amountWei The amount of WEI to be burned and rewarded
    /// @param challenger The address of the challenger
    function _rewardAndBurn(uint256 amountWei, address challenger) internal {
        // Transfer reward to the challenger
        bool success;
        assembly ("memory-safe") {
            success := call(gas(), challenger, amountWei, 0, 0, 0, 0)
        }

        if (!success) revert EthTransferFailed();

        // Burn the rest
        _burnETH(amountWei);
    }
}
