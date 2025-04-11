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

    Config private config;

    constructor(Config memory _config) {
        config = _config;
    }

    /**
     *
     *                                Registration/Unregistration Functions                           *
     *
     */

    /// @notice Batch registers an operator's BLS keys and collateral to the URC
    /// @dev SignedRegistration signatures are optimistically verified. They are expected to be signed with the `DOMAIN_SEPARATOR` mixin.
    /// @dev The function will merkleize the supplied `regs` and map the registration root to an Operator struct.
    /// @dev The function will revert if:
    /// @dev - They sent less than `config.minCollateralWei` (InsufficientCollateral)
    /// @dev - The operator has already registered the same `regs` (OperatorAlreadyRegistered)
    /// @dev - The registration root is invalid (InvalidRegistrationRoot)
    /// @param regs The BLS keys to register
    /// @param owner The authorized address to perform actions on behalf of the operator
    /// @return registrationRoot The merkle root of the registration
    function register(SignedRegistration[] calldata regs, address owner)
        external
        payable
        returns (bytes32 registrationRoot)
    {
        // At least MIN_COLLATERAL for sufficient reward for fraud/equivocation challenges
        if (msg.value < config.minCollateralWei) {
            revert InsufficientCollateral();
        }

        // Include the owner address in the merkleization to prevent frontrunning
        registrationRoot = _merkleizeSignedRegistrationsWithOwner(regs, owner);

        if (registrationRoot == bytes32(0)) {
            revert InvalidRegistrationRoot();
        }

        // Prevent reusing a deleted operator
        if (operators[registrationRoot].data.deleted) {
            revert OperatorDeleted();
        }

        // Prevent duplicates from overwriting previous registrations
        if (operators[registrationRoot].data.registeredAt != 0) {
            revert OperatorAlreadyRegistered();
        }

        // Each Operator is mapped to a unique registration root
        Operator storage newOperator = operators[registrationRoot];
        newOperator.data.owner = owner;
        newOperator.data.collateralWei = uint80(msg.value);
        newOperator.data.numKeys = uint16(regs.length);
        newOperator.data.registeredAt = uint48(block.number);
        newOperator.data.unregisteredAt = type(uint48).max;
        newOperator.data.slashedAt = 0;

        // Store the initial collateral value in the history
        newOperator.collateralHistory.push(
            CollateralRecord({ timestamp: uint64(block.timestamp), collateralValue: uint80(msg.value) })
        );

        emit OperatorRegistered(registrationRoot, msg.value, owner);
    }

    /// @notice Starts the process to unregister an operator from the URC
    /// @dev The function will mark the `unregisteredAt` timestamp in the Operator struct. The operator can claim their collateral after the `unregistrationDelay` more blocks have passed.
    /// @dev The function will revert if:
    /// @dev - The operator has already unregistered (AlreadyUnregistered)
    /// @dev - The operator has not registered (NotRegisteredKey)
    /// @dev - The caller is not the operator's withdrawal address (WrongOperator)
    /// @param registrationRoot The merkle root generated and stored from the register() function
    function unregister(bytes32 registrationRoot) external {
        Operator storage operator = operators[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) {
            revert OperatorDeleted();
        }

        // Only the authorized owner can unregister
        if (operator.data.owner != msg.sender) {
            revert WrongOperator();
        }

        // Prevent double unregistrations
        if (operator.data.unregisteredAt != type(uint48).max) {
            revert AlreadyUnregistered();
        }

        // Prevent a slashed operator from unregistering
        // They must wait for the slash window to pass before calling claimSlashedCollateral()
        if (operator.data.slashedAt != 0) {
            revert SlashingAlreadyOccurred();
        }

        // Save the block number; they must wait for the unregistration delay to claim collateral
        operator.data.unregisteredAt = uint48(block.number);

        emit OperatorUnregistered(registrationRoot);
    }

    /// @notice Opts an operator into a proposer commtiment protocol via Slasher contract
    /// @dev The function will revert if:
    /// @dev - The operator has not registered (NotRegisteredKey)
    /// @dev - The caller is not the operator's owner (WrongOperator)
    /// @dev - The fraud proof window has not passed (FraudProofWindowNotMet)
    /// @dev - The operator has already opted in (AlreadyOptedIn)
    /// @dev - The opt-in delay has not passed (OptInDelayNotMet)
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param slasher The address of the Slasher contract to opt into
    /// @param committer The address of the key used for commitments

    function optInToSlasher(bytes32 registrationRoot, address slasher, address committer) external {
        Operator storage operator = operators[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) {
            revert OperatorDeleted();
        }

        // Only the authorized owner can opt in
        if (operator.data.owner != msg.sender) {
            revert WrongOperator();
        }

        // Operator cannot opt in before the fraud proof window elapses
        if (block.number < operator.data.registeredAt + config.fraudProofWindow) {
            revert FraudProofWindowNotMet();
        }

        // Retrieve the SlasherCommitment struct
        SlasherCommitment storage slasherCommitment = operator.slasherCommitments[slasher];

        // Check if they've been slashed before
        if (slasherCommitment.slashed) {
            revert SlashingAlreadyOccurred();
        }

        // Check if already opted in
        if (slasherCommitment.optedOutAt < slasherCommitment.optedInAt) {
            revert AlreadyOptedIn();
        }

        // Fix: If previously opted out, enforce delay before allowing new opt-in
        // Changed from block.timestamp to block.number to match the optedOutAt type
        if (slasherCommitment.optedOutAt != 0 && block.number < slasherCommitment.optedOutAt + config.optInDelay) {
            revert OptInDelayNotMet();
        }

        // Save the block number and committer
        slasherCommitment.optedInAt = uint48(block.number);
        slasherCommitment.optedOutAt = 0;
        slasherCommitment.committer = committer;

        emit OperatorOptedIn(registrationRoot, slasher, committer);
    }

    /// @notice Opts out of a protocol for an operator
    /// @dev The function will revert if:
    /// @dev - The caller is not the operator's owner (WrongOperator)
    /// @dev - The opt-in delay has not passed (OptInDelayNotMet)
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param slasher The address of the Slasher contract to opt out of
    function optOutOfSlasher(bytes32 registrationRoot, address slasher) external {
        Operator storage operator = operators[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) {
            revert OperatorDeleted();
        }

        // Only the authorized owner can opt out
        if (operator.data.owner != msg.sender) {
            revert WrongOperator();
        }

        // Retrieve the SlasherCommitment struct
        SlasherCommitment storage slasherCommitment = operator.slasherCommitments[slasher];

        // Check if already opted out or never opted in
        if (slasherCommitment.optedOutAt >= slasherCommitment.optedInAt) {
            revert NotOptedIn();
        }

        // Enforce a delay before allowing opt-out
        if (block.number < slasherCommitment.optedInAt + config.optInDelay) {
            revert OptInDelayNotMet();
        }

        // Save the block number
        slasherCommitment.optedOutAt = uint48(block.number);

        emit OperatorOptedOut(registrationRoot, slasher);
    }

    /**
     *
     *                                Slashing Functions                           *
     *
     */

    /// @notice Slash an operator for submitting a fraudulent `SignedRegistration` in the register() function
    /// @dev To save BLS verification gas costs, the URC optimistically accepts registration signatures. This function allows a challenger to slash the operator by executing the BLS verification to prove the registration is fraudulent.
    /// @dev A successful challenge will transfer `config.minCollateralWei / 2` to the challenger, burn `config.minCollateralWei / 2`, and then allow the operator to claim their remaining collateral after `config.slashWindow` blocks have elapsed from the `claimSlashedCollateral()` function.
    /// @dev The function will revert if:
    /// @dev - The operator has already been deleted (OperatorDeleted)
    /// @dev - The fraud proof window has expired (FraudProofWindowExpired)
    /// @dev - The operator has no collateral (NoCollateral)
    /// @dev - The fraud proof is invalid (FraudProofChallengeInvalid)
    /// @dev - ETH transfer to challenger fails (EthTransferFailed)
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @return slashedCollateralWei The amount of WEI slashed
    function slashRegistration(RegistrationProof calldata proof) external returns (uint256 slashedCollateralWei) {
        Operator storage operator = operators[proof.registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) {
            revert OperatorDeleted();
        }

        // Can only slash registrations within the fraud proof window
        if (block.number > operator.data.registeredAt + config.fraudProofWindow) {
            revert FraudProofWindowExpired();
        }

        // 0 collateral implies the registration was not part of the registry or they were previously slashed to 0
        if (operator.data.collateralWei == 0) {
            revert NoCollateral();
        }

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
            operator.data.slashedAt = uint48(block.number);
        }

        // Decrement operator's collateral
        operator.data.collateralWei -= uint80(config.minCollateralWei);

        // Burn half of the MIN_COLLATERAL amount and reward the challenger the other half
        _rewardAndBurn(config.minCollateralWei / 2, msg.sender);

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

    /// @notice Slashes an operator for breaking a commitment
    /// @dev The function verifies `proof` to first ensure the operator's BLS key is in the registry, then verifies the `signedDelegation` was signed by the same key. If the fraud proof window has passed, the URC will call the `slash()` function of the Slasher contract specified in the `signedCommitment`. The Slasher contract will determine if the operator has broken a commitment and return the amount of WEI to be slashed at the URC.
    /// @dev The function will burn `slashAmountWei`. It will also save the timestamp of the slashing to start the `SLASH_WINDOW` in case of multiple slashings.
    /// @dev The function will revert if:
    /// @dev - The operator has already been deleted (OperatorDeleted)
    /// @dev - The same slashing inputs have been supplied before (SlashingAlreadyOccurred)
    /// @dev - The fraud proof window has not passed (FraudProofWindowNotMet)
    /// @dev - The operator has already unregistered (OperatorAlreadyUnregistered)
    /// @dev - The slash window has expired (SlashWindowExpired)
    /// @dev - The merkle proof is invalid (InvalidProof)
    /// @dev - The signed commitment was not signed by the delegated committer (DelegationSignatureInvalid)
    /// @dev - The slash amount exceeds the operator's collateral (SlashAmountExceedsCollateral)
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param delegation The SignedDelegation signed by the operator's BLS key
    /// @param commitment The SignedCommitment signed by the delegate's ECDSA key
    /// @param evidence Arbitrary evidence to slash the operator, required by the Slasher contract
    /// @return slashAmountWei The amount of WEI slashed
    function slashCommitment(
        RegistrationProof calldata proof,
        ISlasher.SignedDelegation calldata delegation,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external returns (uint256 slashAmountWei) {
        Operator storage operator = operators[proof.registrationRoot];
        bytes32 slashingDigest = keccak256(abi.encode(delegation, commitment, proof.registrationRoot));

        // Prevent reusing a deleted operator
        if (operator.data.deleted) {
            revert OperatorDeleted();
        }

        // Prevent slashing with same inputs
        if (slashedBefore[slashingDigest]) {
            revert SlashingAlreadyOccurred();
        }

        // Operator is not liable for slashings before the fraud proof window elapses
        if (block.number < operator.data.registeredAt + config.fraudProofWindow) {
            revert FraudProofWindowNotMet();
        }

        // Operator is not liable for slashings after unregister and the delay has passed
        if (
            operator.data.unregisteredAt != type(uint48).max
                && block.number > operator.data.unregisteredAt + config.unregistrationDelay
        ) {
            revert OperatorAlreadyUnregistered();
        }

        // Slashing can only occur within the slash window after the first reported slashing
        // After the slash window has passed, the operator can claim collateral
        if (operator.data.slashedAt != 0 && block.number > operator.data.slashedAt + config.slashWindow) {
            revert SlashWindowExpired();
        }

        // Verify the delegation was signed by the operator's BLS key
        // This is a sanity check to ensure the delegation is valid
        // It will revert if the registration proof is invalid or the Delegation signature is invalid
        _verifyDelegation(proof, delegation);

        // Verify the commitment was signed by the commitment key from the Delegation
        address committer = ECDSA.recover(keccak256(abi.encode(commitment.commitment)), commitment.signature);
        if (committer != delegation.delegation.committer) {
            revert UnauthorizedCommitment();
        }

        // Save timestamp only once to start the slash window
        if (operator.data.slashedAt == 0) {
            operator.data.slashedAt = uint32(block.number);
        }

        // Prevent same slashing from occurring again
        slashedBefore[slashingDigest] = true;

        // Call the Slasher contract to slash the operator
        slashAmountWei = ISlasher(commitment.commitment.slasher).slash(
            delegation.delegation, commitment.commitment, evidence, msg.sender
        );

        // Prevent slashing more than the operator's collateral
        if (slashAmountWei > operator.data.collateralWei) {
            revert SlashAmountExceedsCollateral();
        }

        // Decrement operator's collateral
        operator.data.collateralWei -= uint80(slashAmountWei);

        // Burn the slashed amount
        _burnETH(slashAmountWei);

        emit OperatorSlashed(
            SlashingType.Commitment,
            proof.registrationRoot,
            operator.data.owner,
            msg.sender,
            commitment.commitment.slasher,
            slashAmountWei
        );
    }

    /// @notice Slashes an operator for breaking a commitment in a protocol they opted into via the optInToSlasher() function. The operator must have already opted into the protocol.
    /// @dev The function verifies the commitment was signed by the registered committer from the optInToSlasher() function before calling into the Slasher contract.
    /// @dev Reverts if:
    /// @dev - The operator has already been deleted (OperatorDeleted)
    /// @dev - The fraud proof window has not passed (FraudProofWindowNotMet)
    /// @dev - The operator has already unregistered and delay passed (OperatorAlreadyUnregistered)
    /// @dev - The slash window has expired (SlashWindowExpired)
    /// @dev - The operator has not opted into the slasher (NotOptedIn)
    /// @dev - The commitment was not signed by registered committer (UnauthorizedCommitment)
    /// @dev - The slash amount exceeds operator's collateral (SlashAmountExceedsCollateral)
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param commitment The SignedCommitment signed by the delegate's ECDSA key
    /// @param evidence Arbitrary evidence to slash the operator, required by the Slasher contract
    /// @return slashAmountWei The amount of WEI slashed
    function slashCommitmentFromOptIn(
        bytes32 registrationRoot,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external returns (uint256 slashAmountWei) {
        Operator storage operator = operators[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) {
            revert OperatorDeleted();
        }

        address slasher = commitment.commitment.slasher;

        // Operator is not liable for slashings before the fraud proof window elapses
        if (block.number < operator.data.registeredAt + config.fraudProofWindow) {
            revert FraudProofWindowNotMet();
        }

        // Operator is not liable for slashings after unregister and the delay has passed
        if (
            operator.data.unregisteredAt != type(uint48).max
                && block.number > operator.data.unregisteredAt + config.unregistrationDelay
        ) {
            revert OperatorAlreadyUnregistered();
        }

        // Slashing can only occur within the slash window after the first reported slashing
        // After the slash window has passed, the operator can claim collateral
        if (operator.data.slashedAt != 0 && block.number > operator.data.slashedAt + config.slashWindow) {
            revert SlashWindowExpired();
        }

        // Recover the SlasherCommitment entry
        SlasherCommitment storage slasherCommitment = operator.slasherCommitments[slasher];

        // Verify the operator is opted into protocol
        if (slasherCommitment.optedInAt <= slasherCommitment.optedOutAt) {
            revert NotOptedIn();
        }

        // Verify the commitment was signed by the registered committer from the optInToSlasher() function
        address committer = ECDSA.recover(keccak256(abi.encode(commitment.commitment)), commitment.signature);
        if (committer != slasherCommitment.committer) {
            revert UnauthorizedCommitment();
        }

        // Save timestamp only once to start the slash window - MOVED BEFORE EXTERNAL CALL
        if (operator.data.slashedAt == 0) {
            operator.data.slashedAt = uint32(block.number);
        }

        // Set the operator's SlasherCommitment to slashed
        slasherCommitment.slashed = true;

        // Call the Slasher contract to slash the operator
        slashAmountWei = ISlasher(slasher).slashFromOptIn(commitment.commitment, evidence, msg.sender);

        // Prevent slashing more than the operator's collateral
        if (slashAmountWei > operator.data.collateralWei) {
            revert SlashAmountExceedsCollateral();
        }

        // Decrement operator's collateral
        operator.data.collateralWei -= uint80(slashAmountWei);

        // Burn the slashed amount
        _burnETH(slashAmountWei);

        emit OperatorSlashed(
            SlashingType.Commitment, registrationRoot, operator.data.owner, msg.sender, slasher, slashAmountWei
        );
    }

    /// @notice Slash an operator for equivocation (signing two different delegations for the same slot)
    /// @dev A successful challenge will transfer `MIN_COLLATERAL / 2` to the challenger, burn `MIN_COLLATERAL / 2`, and then allow the operator to claim their remaining collateral after `SLASH_WINDOW` blocks have elapsed from the `claimSlashedCollateral()` function.
    /// @dev Reverts if:
    /// @dev - The operator has already been deleted (OperatorDeleted)
    /// @dev - The operator has already equivocated (OperatorAlreadyEquivocated)
    /// @dev - The delegations are the same (DelegationsAreSame)
    /// @dev - The fraud proof window has not passed (FraudProofWindowNotMet)
    /// @dev - The operator has already unregistered and delay passed (OperatorAlreadyUnregistered)
    /// @dev - The slash window has expired (SlashWindowExpired)
    /// @dev - Either delegation is invalid (InvalidDelegation)
    /// @dev - The delegations are for different slots (DifferentSlots)
    /// @dev - ETH transfer to challenger fails (EthTransferFailed)
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param delegationOne The first SignedDelegation signed by the operator's BLS key
    /// @param delegationTwo The second SignedDelegation signed by the operator's BLS key
    /// @return slashAmountWei The amount of WEI slashed
    function slashEquivocation(
        RegistrationProof calldata proof,
        ISlasher.SignedDelegation calldata delegationOne,
        ISlasher.SignedDelegation calldata delegationTwo
    ) external returns (uint256 slashAmountWei) {
        Operator storage operator = operators[proof.registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) {
            revert OperatorDeleted();
        }

        // Prevent slashing an operator that has already equivocated
        if (operator.data.equivocated) {
            revert OperatorAlreadyEquivocated();
        }

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
        if (block.number < operator.data.registeredAt + config.fraudProofWindow) {
            revert FraudProofWindowNotMet();
        }

        // Operator is not liable for slashings after unregister and the delay has passed
        if (
            operator.data.unregisteredAt != type(uint48).max
                && block.number > operator.data.unregisteredAt + config.unregistrationDelay
        ) {
            revert OperatorAlreadyUnregistered();
        }

        // Slashing can only occur within the slash window after the first reported slashing
        // After the slash window has passed, the operator can claim collateral
        if (operator.data.slashedAt != 0 && block.number > operator.data.slashedAt + config.slashWindow) {
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
            operator.data.slashedAt = uint48(block.number);
        }

        // Decrement operator's collateral
        operator.data.collateralWei -= uint80(config.minCollateralWei);

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

    /// @notice Adds collateral to an Operator struct
    /// @dev The function will revert if:
    /// @dev - The operator was deleted (OperatorDeleted)
    /// @dev - The operator has not registered (NotRegisteredKey)
    /// @dev - The collateral amount overflows the `collateralWei` field (CollateralOverflow)
    /// @param registrationRoot The merkle root generated and stored from the register() function
    function addCollateral(bytes32 registrationRoot) external payable {
        Operator storage operator = operators[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) {
            revert OperatorDeleted();
        }

        // Zero collateral implies they were previously slashed to 0 or did not exist and must re-register
        if (operator.data.collateralWei == 0) {
            revert NoCollateral();
        }

        if (msg.value > type(uint80).max) {
            revert CollateralOverflow();
        }

        operator.data.collateralWei += uint80(msg.value);

        // Store the updated collateral value in the history
        operator.collateralHistory.push(
            CollateralRecord({ timestamp: uint64(block.timestamp), collateralValue: operator.data.collateralWei })
        );

        emit CollateralAdded(registrationRoot, operator.data.collateralWei);
    }

    /// @notice Claims an operator's collateral after the unregistration delay
    /// @dev The function will revert if:
    /// @dev - The operator has already been deleted (OperatorDeleted)
    /// @dev - The operator has not unregistered (NotUnregistered)
    /// @dev - The `unregistrationDelay` has not passed (UnregistrationDelayNotMet)
    /// @dev - The operator was slashed (need to call `claimSlashedCollateral()`) (SlashingAlreadyOccurred)
    /// @dev - There is no collateral to claim (NoCollateralToClaim)
    /// @dev - ETH transfer to operator fails (EthTransferFailed)
    /// @dev The function will transfer the operator's collateral to their registered `withdrawalAddress`.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    function claimCollateral(bytes32 registrationRoot) external {
        Operator storage operator = operators[registrationRoot];
        address operatorOwner = operator.data.owner;
        uint256 collateralWei = operator.data.collateralWei;

        // Prevent reusing a deleted operator
        if (operator.data.deleted) {
            revert OperatorDeleted();
        }

        // Check that they've unregistered
        if (operator.data.unregisteredAt == type(uint48).max) {
            revert NotUnregistered();
        }

        // Check that enough time has passed
        if (block.number < operator.data.unregisteredAt + config.unregistrationDelay) {
            revert UnregistrationDelayNotMet();
        }

        // Check that the operator has not been slashed
        if (operator.data.slashedAt != 0) {
            revert SlashingAlreadyOccurred();
        }

        // Prevent the Operator from being reused
        operator.data.deleted = true;

        // Transfer to operator
        bool success;
        assembly ("memory-safe") {
            success := call(gas(), operatorOwner, collateralWei, 0, 0, 0, 0)
        }
        if (!success) {
            revert EthTransferFailed();
        }

        emit CollateralClaimed(registrationRoot, collateralWei);
    }

    /// @notice Claims an operator's collateral if they have been slashed before
    /// @dev The function will revert if:
    /// @dev - The operator has already been deleted (OperatorDeleted)
    /// @dev - The operator has not been slashed (NotSlashed)
    /// @dev - The slash window has not passed (SlashWindowNotMet)
    /// @dev - ETH transfer to operator fails (EthTransferFailed)
    function claimSlashedCollateral(bytes32 registrationRoot) external {
        Operator storage operator = operators[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.data.deleted) {
            revert OperatorDeleted();
        }

        address owner = operator.data.owner;
        uint256 collateralWei = operator.data.collateralWei;

        // Check that they've been slashed
        if (operator.data.slashedAt == 0) {
            revert NotSlashed();
        }

        // Check that enough time has passed
        if (block.number < operator.data.slashedAt + config.slashWindow) {
            revert SlashWindowNotMet();
        }

        // Prevent the Operator from being reused
        operator.data.deleted = true;

        // Transfer collateral to owner
        bool success;
        assembly ("memory-safe") {
            success := call(gas(), owner, collateralWei, 0, 0, 0, 0)
        }

        if (!success) {
            revert EthTransferFailed();
        }

        emit CollateralClaimed(registrationRoot, collateralWei);
    }

    /// @notice Retrieves the historical collateral value for an operator at a given timestamp
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param timestamp The timestamp to retrieve the collateral value for
    /// @return collateralWei The collateral amount in WEI at the closest recorded timestamp
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

    /**
     *
     *                                Getter Functions                           *
     *
     */

    /// @notice Get the configuration of the registry
    /// @return config The configuration of the registry
    function getConfig() external view returns (Config memory) {
        return config;
    }

    /// @notice Get the data about an operator
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @return operatorData The data about the operator
    function getOperatorData(bytes32 registrationRoot) external view returns (OperatorData memory operatorData) {
        operatorData = operators[registrationRoot].data;
    }

    /// @notice Verify a merkle proof against a given `RegistrationProof`
    /// @dev The function will revert if the proof is invalid
    /// @param proof The merkle proof to verify the operator's key is in the registry
    function verifyMerkleProof(RegistrationProof calldata proof) external view {
        _verifyMerkleProof(proof);
    }

    /// @notice Checks if an operator is opted into a protocol
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param slasher The address of the slasher to check
    /// @return slasherCommitment The slasher commitment (default values if not opted in)
    function getSlasherCommitment(bytes32 registrationRoot, address slasher)
        external
        view
        returns (SlasherCommitment memory)
    {
        return operators[registrationRoot].slasherCommitments[slasher];
    }

    /// @notice Checks if an operator is opted into a protocol
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param slasher The address of the slasher to check
    /// @return True if the operator is opted in and hasn't been slashed, false otherwise
    function isOptedIntoSlasher(bytes32 registrationRoot, address slasher) external view returns (bool) {
        SlasherCommitment memory slasherCommitment = operators[registrationRoot].slasherCommitments[slasher];
        return slasherCommitment.optedOutAt < slasherCommitment.optedInAt && !slasherCommitment.slashed;
    }

    /// @notice Returns the operator data for a given `RegistrationProof` iff the proof is valid
    /// @dev The function will revert if the proof is invalid
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @return operatorData The operator data
    function getVerifiedOperatorData(RegistrationProof calldata proof) external view returns (OperatorData memory) {
        OperatorData memory operatorData = operators[proof.registrationRoot].data;

        // Revert if the proof is invalid
        _verifyMerkleProof(proof);

        return operatorData;
    }

    /// @notice Checks if a slashing has already occurred with the same input
    /// @dev The getter for the `slashedBefore` mapping
    /// @param slashingDigest The digest of the slashing evidence
    /// @return True if the slashing has already occurred, false otherwise
    function slashingEvidenceAlreadyUsed(bytes32 slashingDigest) external view returns (bool) {
        return slashedBefore[slashingDigest];
    }

    /// @notice Returns a `RegistrationProof` for a given `SignedRegistration` array
    /// @dev This function is not intended to be called on-chain due to gas costs
    /// @param regs The array of `SignedRegistration` structs to create a proof for
    /// @param owner The owner address of the operator
    /// @param leafIndex The index of the leaf the proof is for
    /// @return proof The `RegistrationProof` for the given `SignedRegistration` array
    function getRegistrationProof(SignedRegistration[] calldata regs, address owner, uint256 leafIndex)
        external
        pure
        returns (RegistrationProof memory proof)
    {
        proof.registrationRoot = _merkleizeSignedRegistrationsWithOwner(regs, owner);
        proof.registration = regs[leafIndex];
        proof.leafIndex = leafIndex;

        bytes32[] memory leaves = _hashToLeaves(regs, owner);
        proof.merkleProof = MerkleTree.generateProof(leaves, leafIndex);
    }

    /**
     *
     *                                Helper Functions                           *
     *
     */

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
    /// @dev The function checks against registered operators to get the owner address
    /// @param proof The merkle proof to verify the operator's key is in the registry
    function _verifyMerkleProof(RegistrationProof calldata proof) internal view {
        address owner = operators[proof.registrationRoot].data.owner;
        bytes32 leaf = keccak256(abi.encode(proof.registration, owner));
        if (!MerkleTree.verifyProofCalldata(proof.registrationRoot, leaf, proof.leafIndex, proof.merkleProof)) {
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
        if (!success) {
            revert EthTransferFailed();
        }
    }

    /// @notice Burns `amountWei` ether and rewards `amountWei` the challenger
    /// @dev The function will revert if the transfer to the challenger fails.
    /// @dev In total the total WEI leaving the contract is `2 * amountWei`
    /// @param amountWei The amount of WEI to be burned and rewarded
    /// @param challenger The address of the challenger
    function _rewardAndBurn(uint256 amountWei, address challenger) internal {
        // Transfer reward to the challenger
        bool success;
        assembly ("memory-safe") {
            success := call(gas(), challenger, amountWei, 0, 0, 0, 0)
        }

        if (!success) {
            revert EthTransferFailed();
        }

        // Burn the rest
        _burnETH(amountWei);
    }
}
