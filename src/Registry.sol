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
    mapping(bytes32 registrationRoot => Operator) public registrations;

    /// @notice Mapping to track if a slashing has occurred before with same input
    mapping(bytes32 slashingDigest => bool) public slashedBefore;

    // Constants
    uint256 public constant MIN_COLLATERAL = 0.1 ether;
    uint256 public constant UNREGISTRATION_DELAY = 7200; // 1 day
    uint256 public constant FRAUD_PROOF_WINDOW = 7200; // 1 day
    uint32 public constant SLASH_WINDOW = 7200; // 1 day
    uint32 public constant OPT_IN_DELAY = 7200; // 1 day
    address internal constant BURNER_ADDRESS = address(0x0000000000000000000000000000000000000000);
    bytes public constant REGISTRATION_DOMAIN_SEPARATOR = "0x00435255"; // "URC" in little endian
    bytes public constant DELEGATION_DOMAIN_SEPARATOR = "0x0044656c"; // "Del" in little endian

    /**
     *
     *                                Registration/Unregistration Functions                           *
     *
     */

    /// @notice Batch registers an operator's BLS keys and collateral to the URC
    /// @dev Registration signatures are optimistically verified. They are expected to be signed with the `DOMAIN_SEPARATOR` mixin.
    /// @dev The function will merkleize the supplied `regs` and map the registration root to an Operator struct.
    /// @dev The function will revert if:
    /// @dev - They sent less than `MIN_COLLATERAL` (InsufficientCollateral)
    /// @dev - The operator has already registered the same `regs` (OperatorAlreadyRegistered)
    /// @dev - The registration root is invalid (InvalidRegistrationRoot)
    /// @param regs The BLS keys to register
    /// @param owner The authorized address to perform actions on behalf of the operator
    /// @return registrationRoot The merkle root of the registration
    function register(Registration[] calldata regs, address owner)
        external
        payable
        returns (bytes32 registrationRoot)
    {
        // At least MIN_COLLATERAL for sufficient reward for fraud/equivocation challenges
        if (msg.value < MIN_COLLATERAL) {
            revert InsufficientCollateral();
        }

        // Construct tree root from registrations
        registrationRoot = _merkleizeRegistrations(regs);

        if (registrationRoot == bytes32(0)) {
            revert InvalidRegistrationRoot();
        }

        // Prevent duplicates from overwriting previous registrations
        if (registrations[registrationRoot].registeredAt != 0) {
            revert OperatorAlreadyRegistered();
        }

        // Each Operator is mapped to a unique registration root
        Operator storage newOperator = registrations[registrationRoot];
        newOperator.owner = owner;
        newOperator.collateralGwei = uint56(msg.value / 1 gwei);
        newOperator.numKeys = uint8(regs.length);
        newOperator.registeredAt = uint32(block.number);
        newOperator.unregisteredAt = type(uint32).max;
        newOperator.slashedAt = 0;

        // Store the initial collateral value in the history
        newOperator.collateralHistory.push(
            CollateralRecord({ timestamp: uint64(block.timestamp), collateralValue: uint56(msg.value / 1 gwei) })
        );

        emit OperatorRegistered(registrationRoot, uint56(msg.value / 1 gwei), owner);
    }

    /// @notice Starts the process to unregister an operator from the URC
    /// @dev The function will mark the `unregisteredAt` timestamp in the Operator struct. The operator can claim their collateral after the `unregistrationDelay` more blocks have passed.
    /// @dev The function will revert if:
    /// @dev - The operator has already unregistered (AlreadyUnregistered)
    /// @dev - The operator has not registered (NotRegisteredKey)
    /// @dev - The caller is not the operator's withdrawal address (WrongOperator)
    /// @param registrationRoot The merkle root generated and stored from the register() function
    function unregister(bytes32 registrationRoot) external {
        Operator storage operator = registrations[registrationRoot];

        // Only the authorized owner can unregister
        if (operator.owner != msg.sender) {
            revert WrongOperator();
        }

        // Prevent double unregistrations
        if (operator.unregisteredAt != type(uint32).max) {
            revert AlreadyUnregistered();
        }

        // Prevent a slashed operator from unregistering
        // They must wait for the slash window to pass before calling claimSlashedCollateral()
        if (operator.slashedAt != 0) {
            revert SlashingAlreadyOccurred();
        }

        // Save the block number; they must wait for the unregistration delay to claim collateral
        operator.unregisteredAt = uint32(block.number);

        emit OperatorUnregistered(registrationRoot, operator.unregisteredAt);
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
        Operator storage operator = registrations[registrationRoot];

        // Only the authorized owner can opt in
        if (operator.owner != msg.sender) {
            revert WrongOperator();
        }

        // Operator cannot opt in before the fraud proof window elapses
        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        // Retrieve the SlasherCommitment struct
        SlasherCommitment storage slasherCommitment = operator.slasherCommitments[slasher];

        // Check if already opted in
        if (slasherCommitment.optedOutAt < slasherCommitment.optedInAt) {
            revert AlreadyOptedIn();
        }

        // If previously opted out, enforce delay before allowing new opt-in
        if (slasherCommitment.optedOutAt != 0 && block.timestamp < slasherCommitment.optedOutAt + OPT_IN_DELAY) {
            revert OptInDelayNotMet();
        }

        // Save the block number and committer
        slasherCommitment.optedInAt = uint64(block.number);
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
        Operator storage operator = registrations[registrationRoot];

        // Only the authorized owner can opt out
        if (operator.owner != msg.sender) {
            revert WrongOperator();
        }

        // Retrieve the SlasherCommitment struct
        SlasherCommitment storage slasherCommitment = operator.slasherCommitments[slasher];

        // Check if already opted out or never opted in
        if (slasherCommitment.optedOutAt >= slasherCommitment.optedInAt) {
            revert NotOptedIn();
        }

        // Enforce a delay before allowing opt-out
        if (block.number < slasherCommitment.optedInAt + OPT_IN_DELAY) {
            revert OptInDelayNotMet();
        }

        // Save the block number
        slasherCommitment.optedOutAt = uint64(block.number);

        emit OperatorOptedOut(registrationRoot, slasher);
    }

    /**
     *
     *                                Slashing Functions                           *
     *
     */

    /// @notice Slash an operator for submitting a fraudulent `Registration` in the register() function
    /// @dev To save BLS verification gas costs, the URC optimistically accepts registration signatures. This function allows a challenger to slash the operator by executing the BLS verification to prove the registration is fraudulent.
    /// @dev The function will delete the operator's registration, transfer `MIN_COLLATERAL` to the caller, and return any remaining funds to the operator's withdrawal address.
    /// @dev The function will revert if:
    /// @dev - The operator has already unregistered (AlreadyUnregistered)
    /// @dev - The operator has not registered (NotRegisteredKey)
    /// @dev - The fraud proof window has expired (FraudProofWindowExpired)
    /// @dev - The proof is invalid (FraudProofChallengeInvalid)
    /// @dev - ETH transfer to challenger or owner fails (EthTransferFailed)
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param reg The fraudulent Registration
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @return slashedCollateralWei The amount of GWEI slashed
    function slashRegistration(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external returns (uint256 slashedCollateralWei) {
        Operator storage operator = registrations[registrationRoot];
        address owner = operator.owner;

        // Can only slash registrations within the fraud proof window
        if (block.number > operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowExpired();
        }

        // Verify the registration is part of the registry
        uint256 collateralGwei = _verifyMerkleProof(registrationRoot, keccak256(abi.encode(reg)), proof, leafIndex);

        // 0 collateral implies the registration was not part of the registry
        if (collateralGwei == 0) {
            revert NotRegisteredKey();
        }

        // Reconstruct registration message
        bytes memory message = abi.encode(owner);

        // Verify registration signature, note the domain separator mixin
        if (BLS.verify(message, reg.signature, reg.pubkey, REGISTRATION_DOMAIN_SEPARATOR)) {
            revert FraudProofChallengeInvalid();
        }

        // Delete the operator, they must re-register to continue
        delete registrations[registrationRoot];

        // Calculate the amount to transfer to challenger and return to owner
        uint256 remainingWei = uint256(collateralGwei) * 1 gwei - MIN_COLLATERAL;

        // Transfer to the challenger
        (bool success,) = msg.sender.call{ value: MIN_COLLATERAL }("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Return any remaining funds to owner
        (success,) = owner.call{ value: remainingWei }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit OperatorSlashed(SlashingType.Fraud, registrationRoot, owner, msg.sender, address(this), MIN_COLLATERAL);

        // Return a value for the caller to use
        return MIN_COLLATERAL;
    }

    /// @notice Slashes an operator for breaking a commitment
    /// @dev The function verifies `proof` to first ensure the operator's BLS key is in the registry, then verifies the `signedDelegation` was signed by the same key. If the fraud proof window has passed, the URC will call the `slash()` function of the Slasher contract specified in the `signedCommitment`. The Slasher contract will determine if the operator has broken a commitment and return the amount of GWEI to be slashed at the URC.
    /// @dev The function will burn `slashAmountGwei`. It will also save the timestamp of the slashing to start the `SLASH_WINDOW` in case of multiple slashings.
    /// @dev The function will revert if:
    /// @dev - The same slashing inputs have been supplied before (SlashingAlreadyOccurred)
    /// @dev - The fraud proof window has not passed (FraudProofWindowNotMet)
    /// @dev - The operator has already unregistered (OperatorAlreadyUnregistered)
    /// @dev - The slash window has expired (SlashWindowExpired)
    /// @dev - The proof is invalid (NotRegisteredKey)
    /// @dev - The signed commitment was not signed by the delegated committer (DelegationSignatureInvalid)
    /// @dev - The slash amount exceeds the operator's collateral (SlashAmountExceedsCollateral)
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param registrationSignature The signature from the operator's previously registered `Registration`
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @param delegation The SignedDelegation signed by the operator's BLS key
    /// @param commitment The SignedCommitment signed by the delegate's ECDSA key
    /// @param evidence Arbitrary evidence to slash the operator, required by the Slasher contract
    /// @return slashAmountGwei The amount of GWEI slashed
    function slashCommitment(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegation,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external returns (uint256 slashAmountGwei) {
        Operator storage operator = registrations[registrationRoot];

        bytes32 slashingDigest = keccak256(abi.encode(delegation, commitment, registrationRoot));

        // Prevent slashing with same inputs
        if (slashedBefore[slashingDigest]) {
            revert SlashingAlreadyOccurred();
        }

        // Operator is not liable for slashings before the fraud proof window elapses
        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        // Operator is not liable for slashings after unregister and the delay has passed
        if (
            operator.unregisteredAt != type(uint32).max && block.number > operator.unregisteredAt + UNREGISTRATION_DELAY
        ) {
            revert OperatorAlreadyUnregistered();
        }

        // Slashing can only occur within the slash window after the first reported slashing
        // After the slash window has passed, the operator can claim collateral
        if (operator.slashedAt != 0 && block.number > operator.slashedAt + SLASH_WINDOW) {
            revert SlashWindowExpired();
        }

        // Verify the delegation was signed by the operator's BLS key
        // This is a sanity check to ensure the delegation is valid
        uint256 collateralGwei =
            _verifyDelegation(registrationRoot, registrationSignature, proof, leafIndex, delegation);

        // Verify the commitment was signed by the commitment key from the Delegation
        address committer = ECDSA.recover(keccak256(abi.encode(commitment.commitment)), commitment.signature);
        if (committer != delegation.delegation.committer) {
            revert UnauthorizedCommitment();
        }

        // Call the Slasher contract to slash the operator
        slashAmountGwei = ISlasher(commitment.commitment.slasher).slash(
            delegation.delegation, commitment.commitment, evidence, msg.sender
        );

        // Prevent slashing more than the operator's collateral
        if (slashAmountGwei > collateralGwei) {
            revert SlashAmountExceedsCollateral();
        }

        // Burn the slashed amount
        _burnGwei(slashAmountGwei);

        // Save timestamp only once to start the slash window
        if (operator.slashedAt == 0) {
            operator.slashedAt = uint32(block.number);
        }

        // Decrement operator's collateral
        operator.collateralGwei -= uint56(slashAmountGwei);

        // Prevent same slashing from occurring again
        slashedBefore[slashingDigest] = true;

        emit OperatorSlashed(
            SlashingType.Commitment,
            registrationRoot,
            operator.owner,
            msg.sender,
            commitment.commitment.slasher,
            slashAmountGwei
        );
    }

    /// @notice Slashes an operator for breaking a commitment in a protocol they opted into via the optInToSlasher() function. The operator must have already opted into the protocol.
    /// @dev The function verifies the commitment was signed by the registered committer from the optInToSlasher() function before calling into the Slasher contract.
    /// @dev Reverts if:
    /// @dev - The fraud proof window has not passed (FraudProofWindowNotMet)
    /// @dev - The operator has already unregistered and delay passed (OperatorAlreadyUnregistered)
    /// @dev - The slash window has expired (SlashWindowExpired)
    /// @dev - The operator has not opted into the slasher (NotOptedIn)
    /// @dev - The commitment was not signed by registered committer (UnauthorizedCommitment)
    /// @dev - The slash amount exceeds operator's collateral (SlashAmountExceedsCollateral)
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param commitment The SignedCommitment signed by the delegate's ECDSA key
    /// @param evidence Arbitrary evidence to slash the operator, required by the Slasher contract
    function slashCommitmentFromOptIn(
        bytes32 registrationRoot,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external returns (uint256 slashAmountGwei) {
        Operator storage operator = registrations[registrationRoot];
        address slasher = commitment.commitment.slasher;

        // Operator is not liable for slashings before the fraud proof window elapses
        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        // Operator is not liable for slashings after unregister and the delay has passed
        if (
            operator.unregisteredAt != type(uint32).max && block.number > operator.unregisteredAt + UNREGISTRATION_DELAY
        ) {
            revert OperatorAlreadyUnregistered();
        }

        // Slashing can only occur within the slash window after the first reported slashing
        // After the slash window has passed, the operator can claim collateral
        if (operator.slashedAt != 0 && block.number > operator.slashedAt + SLASH_WINDOW) {
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

        // Call the Slasher contract to slash the operator
        slashAmountGwei = ISlasher(slasher).slashFromOptIn(commitment.commitment, evidence, msg.sender);

        // Prevent slashing more than the operator's collateral
        if (slashAmountGwei > operator.collateralGwei) {
            revert SlashAmountExceedsCollateral();
        }

        // Save timestamp only once to start the slash window
        if (operator.slashedAt == 0) {
            operator.slashedAt = uint32(block.number);
        }

        // Decrement operator's collateral
        operator.collateralGwei -= uint56(slashAmountGwei);

        // Prevent same slashing from occurring again
        delete operator.slasherCommitments[slasher];

        emit OperatorSlashed(
            SlashingType.Commitment, registrationRoot, operator.owner, msg.sender, slasher, slashAmountGwei
        );

        // Burn the slashed amount
        _burnGwei(slashAmountGwei);
    }

    /// @notice Slash an operator for equivocation (signing two different delegations for the same slot)
    /// @dev The function will slash the operator's collateral and transfer `MIN_COLLATERAL` to the msg.sender.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param registrationSignature The signature from the operator's previously registered `Registration`
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @param delegationOne The first SignedDelegation signed by the operator's BLS key
    /// @param delegationTwo The second SignedDelegation signed by the operator's BLS key
    /// @dev Reverts if:
    /// @dev - The delegations are the same (DelegationsAreSame)
    /// @dev - The slashing has already occurred (SlashingAlreadyOccurred)
    /// @dev - The fraud proof window has not passed (FraudProofWindowNotMet)
    /// @dev - The operator has already unregistered and delay passed (OperatorAlreadyUnregistered)
    /// @dev - The slash window has expired (SlashWindowExpired)
    /// @dev - Either delegation is invalid (InvalidDelegation)
    /// @dev - The delegations are for different slots (DifferentSlots)
    function slashEquivocation(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegationOne,
        ISlasher.SignedDelegation calldata delegationTwo
    ) external returns (uint256 slashAmountGwei) {
        Operator storage operator = registrations[registrationRoot];

        bytes32 slashingDigest = keccak256(abi.encode(delegationOne, delegationTwo, registrationRoot));

        // Verify the delegations are not identical
        if (keccak256(abi.encode(delegationOne)) == keccak256(abi.encode(delegationTwo))) {
            revert DelegationsAreSame();
        }

        // Prevent duplicate slashing with same inputs
        if (slashedBefore[slashingDigest]) {
            revert SlashingAlreadyOccurred();
        }

        // Operator is not liable for slashings before the fraud proof window elapses
        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        // Operator is not liable for slashings after unregister and the delay has passed
        if (
            operator.unregisteredAt != type(uint32).max && block.number > operator.unregisteredAt + UNREGISTRATION_DELAY
        ) {
            revert OperatorAlreadyUnregistered();
        }

        // Slashing can only occur within the slash window after the first reported slashing
        // After the slash window has passed, the operator can claim collateral
        if (operator.slashedAt != 0 && block.number > operator.slashedAt + SLASH_WINDOW) {
            revert SlashWindowExpired();
        }

        // Verify both delegations were signed by the operator's BLS key
        if (_verifyDelegation(registrationRoot, registrationSignature, proof, leafIndex, delegationOne) == 0) {
            revert InvalidDelegation();
        }
        // error if either delegation is invalid
        if (_verifyDelegation(registrationRoot, registrationSignature, proof, leafIndex, delegationTwo) == 0) {
            revert InvalidDelegation();
        }

        // Verify the delegations are for the same slot
        if (delegationOne.delegation.slot != delegationTwo.delegation.slot) {
            revert DifferentSlots();
        }

        // Save timestamp only once to start the slash window
        if (operator.slashedAt == 0) {
            operator.slashedAt = uint32(block.number);
        }

        slashAmountGwei = MIN_COLLATERAL / 1 gwei;

        // Decrement operator's collateral
        operator.collateralGwei -= uint56(slashAmountGwei);

        // Prevent same slashing from occurring again
        slashedBefore[slashingDigest] = true;

        // Save the perumutation to prevent duplicate slashings with the same pair of Delegations
        slashedBefore[keccak256(abi.encode(delegationTwo, delegationOne, registrationRoot))] = true;

        // Reward the challenger
        (bool success,) = msg.sender.call{ value: MIN_COLLATERAL }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit OperatorSlashed(
            SlashingType.Equivocation, registrationRoot, operator.owner, msg.sender, address(this), slashAmountGwei
        );
    }

    /**
     *
     *                                Collateral Functions                           *
     *
     */

    /// @notice Adds collateral to an Operator struct
    /// @dev The function will revert if the operator does not exist or if the collateral amount overflows the `collateralGwei` field.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    function addCollateral(bytes32 registrationRoot) external payable {
        Operator storage operator = registrations[registrationRoot];
        if (operator.collateralGwei == 0) {
            revert NotRegisteredKey();
        }

        if (msg.value / 1 gwei > type(uint56).max) {
            revert CollateralOverflow();
        }

        operator.collateralGwei += uint56(msg.value / 1 gwei);

        // Store the updated collateral value in the history
        operator.collateralHistory.push(
            CollateralRecord({ timestamp: uint64(block.timestamp), collateralValue: operator.collateralGwei })
        );

        emit CollateralAdded(registrationRoot, operator.collateralGwei);
    }

    /// @notice Claims an operator's collateral after the unregistration delay
    /// @dev The function will revert if the operator does not exist, if the operator has not unregistered, if the `unregistrationDelay` has not passed, or if there is no collateral to claim.
    /// @dev The function will transfer the operator's collateral to their registered `withdrawalAddress`.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    function claimCollateral(bytes32 registrationRoot) external {
        Operator storage operator = registrations[registrationRoot];
        address operatorOwner = operator.owner;
        uint256 collateralGwei = operator.collateralGwei;

        // Check that they've unregistered
        if (operator.unregisteredAt == type(uint32).max) {
            revert NotUnregistered();
        }

        // Check that enough time has passed
        if (block.number < operator.unregisteredAt + UNREGISTRATION_DELAY) {
            revert UnregistrationDelayNotMet();
        }

        // Check that the operator has not been slashed
        if (operator.slashedAt != 0) {
            revert SlashingAlreadyOccurred();
        }

        // Check there's collateral to claim
        if (collateralGwei == 0) {
            revert NoCollateralToClaim();
        }

        // Clear operator info
        delete registrations[registrationRoot];

        // Transfer to operator
        (bool success,) = operatorOwner.call{ value: collateralGwei * 1 gwei }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit CollateralClaimed(registrationRoot, collateralGwei);
    }

    function claimSlashedCollateral(bytes32 registrationRoot) external {
        Operator storage operator = registrations[registrationRoot];
        address owner = operator.owner;
        uint256 collateralGwei = operator.collateralGwei;

        // Check that they've been slashed
        if (operator.slashedAt == 0) {
            revert NotSlashed();
        }

        // Check that enough time has passed
        if (block.number < operator.slashedAt + SLASH_WINDOW) {
            revert SlashWindowNotMet();
        }

        // Delete the operator
        delete registrations[registrationRoot];

        // Transfer collateral to owner
        (bool success,) = owner.call{ value: collateralGwei * 1 gwei }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit CollateralClaimed(registrationRoot, collateralGwei);
    }

    /// @notice Retrieves the historical collateral value for an operator at a given timestamp
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param timestamp The timestamp to retrieve the collateral value for
    /// @return collateralGwei The collateral amount in GWEI at the closest recorded timestamp
    function getHistoricalCollateral(bytes32 registrationRoot, uint256 timestamp)
        external
        view
        returns (uint256 collateralGwei)
    {
        CollateralRecord[] storage records = registrations[registrationRoot].collateralHistory;
        if (records.length == 0) {
            return 0; // No history available
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

    /// @notice Verify a merkle proof against a given `registrationRoot`
    /// @dev The function will return the operator's collateral amount if the proof is valid or 0 if the proof is invalid.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param leaf The leaf to verify
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @return collateralGwei The collateral amount in GWEI
    function verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        external
        view
        returns (uint256 collateralGwei)
    {
        collateralGwei = _verifyMerkleProof(registrationRoot, leaf, proof, leafIndex);
    }

    /// @notice Checks if an operator is opted into a protocol
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param slasher The address of the slasher to check
    /// @return slasherCommitment The slasher commitment (default values if not opted in)
    function getSlasherCommitment(bytes32 registrationRoot, address slasher)
        external
        view
        returns (SlasherCommitment memory slasherCommitment)
    {
        Operator storage operator = registrations[registrationRoot];
        slasherCommitment = operator.slasherCommitments[slasher];
    }

    /// @notice Checks if an operator is opted into a protocol
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param slasher The address of the slasher to check
    /// @return True if the operator is opted in, false otherwise
    function isOptedIntoSlasher(bytes32 registrationRoot, address slasher) external view returns (bool) {
        Operator storage operator = registrations[registrationRoot];
        return operator.slasherCommitments[slasher].optedOutAt < operator.slasherCommitments[slasher].optedInAt;
    }

    /// @notice Get the committer for an operator's slasher commitment
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param reg The registration to verify
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @param slasher The address of the slasher to check
    /// @return slasherCommitment The slasher commitment (default values if not opted in)
    /// @return collateralGwei The collateral amount in GWEI (0 if not opted in)
    function getOptedInCommitter(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex,
        address slasher
    ) external view returns (SlasherCommitment memory slasherCommitment, uint256 collateralGwei) {
        Operator storage operator = registrations[registrationRoot];
        slasherCommitment = operator.slasherCommitments[slasher];

        collateralGwei = _verifyMerkleProof(registrationRoot, keccak256(abi.encode(reg)), proof, leafIndex);
    }

    /**
     *
     *                                Helper Functions                           *
     *
     */

    /// @notice Merkleizes an array of `Registration` structs
    /// @dev Leaves are created by abi-encoding the `Registration` structs, then hashing with keccak256.
    /// @param regs The array of `Registration` structs to merkleize
    /// @return registrationRoot The merkle root of the registration
    function _merkleizeRegistrations(Registration[] calldata regs) internal returns (bytes32 registrationRoot) {
        // Create leaves array with padding
        bytes32[] memory leaves = new bytes32[](regs.length);

        // Create leaf nodes by hashing Registration structs
        for (uint256 i = 0; i < regs.length; i++) {
            leaves[i] = keccak256(abi.encode(regs[i]));
            emit KeyRegistered(i, regs[i], leaves[i]);
        }

        registrationRoot = MerkleTree.generateTree(leaves);
    }

    /// @notice Verifies a merkle proof against a given `registrationRoot`
    /// @dev The function will return the operator's collateral amount if the proof is valid or 0 if the proof is invalid.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param leaf The leaf to verify
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @return collateralGwei The collateral amount in GWEI
    function _verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        internal
        view
        returns (uint256 collateralGwei)
    {
        if (MerkleTree.verifyProofCalldata(registrationRoot, leaf, leafIndex, proof)) {
            collateralGwei = registrations[registrationRoot].collateralGwei;
        }
    }

    /// @notice Verifies a delegation was signed by a registered operator's key
    /// @dev The function will return the operator's collateral amount if the proof is valid or 0 if the proof is invalid.
    /// @dev The `signedDelegation.signature` is expected to be the abi-encoded `Delegation` message mixed with the URC's `DELEGATION_DOMAIN_SEPARATOR`.
    /// @dev The function will revert if the delegation message expired, if the delegation signature is invalid, or if the delegation is not signed by the operator's BLS key.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param registrationSignature The signature from the operator's previously registered `Registration`
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @param delegation The SignedDelegation signed by the operator's BLS key
    /// @return collateralGwei The collateral amount in GWEI
    function _verifyDelegation(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegation
    ) internal view returns (uint256 collateralGwei) {
        // Reconstruct leaf using pubkey in SignedDelegation to check equivalence
        bytes32 leaf = keccak256(abi.encode(delegation.delegation.proposer, registrationSignature));

        collateralGwei = _verifyMerkleProof(registrationRoot, leaf, proof, leafIndex);

        if (collateralGwei == 0) {
            revert NotRegisteredKey();
        }

        // Reconstruct Delegation message
        bytes memory message = abi.encode(delegation.delegation);

        if (!BLS.verify(message, delegation.signature, delegation.delegation.proposer, DELEGATION_DOMAIN_SEPARATOR)) {
            revert DelegationSignatureInvalid();
        }
    }

    /// @notice Burns ether
    /// @dev The function will revert if the transfer to the BURNER_ADDRESS fails.
    /// @param amountGwei The amount of GWEI to be burned
    function _burnGwei(uint256 amountGwei) internal {
        // Burn the slash amount
        (bool success,) = BURNER_ADDRESS.call{ value: amountGwei * 1 gwei }("");
        if (!success) {
            revert EthTransferFailed();
        }
    }
}
