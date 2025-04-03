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

    /// @notice Mapping to track if a slot has been slashed for equivocation
    mapping(uint64 slot => bool) public slashedSlots;

    mapping(bytes32 registrationRoot => PendingSlash) public pendingSlashes;

    // Constants
    uint32 public constant SLASH_WAITING_PERIOD = 1800;
    uint256 public constant MIN_COLLATERAL = 0.1 ether;
    uint256 public constant UNREGISTRATION_DELAY = 7200; // 1 day
    uint256 public constant FRAUD_PROOF_WINDOW = 7200; // 1 day
    uint32 public constant SLASH_WINDOW = 7200; // 1 day
    uint32 public constant OPT_IN_DELAY = 7200; // 1 day
    address internal constant BURNER_ADDRESS = address(0x0000000000000000000000000000000000000000);
    bytes public constant REGISTRATION_DOMAIN_SEPARATOR = "0x00555243"; // "URC" in little endian
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
        // Add dust check
        if (msg.value % 1 wei != 0) {
            revert DustAmountNotAllowed();
        }

        // At least MIN_COLLATERAL for sufficient reward for fraud/equivocation challenges
        if (msg.value < MIN_COLLATERAL) {
            revert InsufficientCollateral();
        }

        // Include the owner address in the merkleization to prevent frontrunning
        registrationRoot = _merkleizeRegistrationsWithOwner(regs, owner);

        if (registrationRoot == bytes32(0)) {
            revert InvalidRegistrationRoot();
        }

        // Prevent reusing a deleted operator
        if (registrations[registrationRoot].deleted) {
            revert OperatorDeleted();
        }

        // Prevent duplicates from overwriting previous registrations
        if (registrations[registrationRoot].registeredAt != 0) {
            revert OperatorAlreadyRegistered();
        }

        // Each Operator is mapped to a unique registration root
        Operator storage newOperator = registrations[registrationRoot];
        newOperator.owner = owner;
        newOperator.collateralWei = uint80(msg.value);
        newOperator.numKeys = uint16(regs.length);
        newOperator.registeredAt = uint48(block.number);
        newOperator.unregisteredAt = type(uint48).max;
        newOperator.slashedAt = 0;

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
        Operator storage operator = registrations[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.deleted) {
            revert OperatorDeleted();
        }

        // Only the authorized owner can unregister
        if (operator.owner != msg.sender) {
            revert WrongOperator();
        }

        // Prevent double unregistrations
        if (operator.unregisteredAt != type(uint48).max) {
            revert AlreadyUnregistered();
        }

        // Prevent a slashed operator from unregistering
        // They must wait for the slash window to pass before calling claimSlashedCollateral()
        if (operator.slashedAt != 0) {
            revert SlashingAlreadyOccurred();
        }

        // Save the block number; they must wait for the unregistration delay to claim collateral
        operator.unregisteredAt = uint48(block.number);

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
        Operator storage operator = registrations[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.deleted) {
            revert OperatorDeleted();
        }

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

        // Fix: If previously opted out, enforce delay before allowing new opt-in
        // Changed from block.timestamp to block.number to match the optedOutAt type
        if (slasherCommitment.optedOutAt != 0 && block.number < slasherCommitment.optedOutAt + OPT_IN_DELAY) {
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

        // Prevent reusing a deleted operator
        if (operator.deleted) {
            revert OperatorDeleted();
        }

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
    /// @dev A successful challenge will transfer `MIN_COLLATERAL / 2` to the challenger, burn `MIN_COLLATERAL / 2`, and then allow the operator to claim their remaining collateral after `SLASH_WINDOW` blocks have elapsed from the `claimSlashedCollateral()` function.
    /// @dev The function will revert if:
    /// @dev - The operator has already been deleted (OperatorDeleted)
    /// @dev - The fraud proof window has expired (FraudProofWindowExpired)
    /// @dev - The operator has not registered (NotRegisteredKey)
    /// @dev - The proof is invalid (FraudProofChallengeInvalid)
    /// @dev - ETH transfer to challenger fails (EthTransferFailed)
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param reg The fraudulent Registration
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @return slashedCollateralWei The amount of WEI slashed
    function slashRegistration(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external returns (uint256 slashedCollateralWei) {
        Operator storage operator = registrations[registrationRoot];
        address owner = operator.owner;
        uint256 collateralWei = operator.collateralWei;

        // Prevent reusing a deleted operator
        if (operator.deleted) {
            revert OperatorDeleted();
        }

        // Can only slash registrations within the fraud proof window
        if (block.number > operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowExpired();
        }

        // Verify the registration is part of the registry
        uint256 verifiedCollateralGwei =
            _verifyMerkleProof(registrationRoot, keccak256(abi.encode(reg, owner)), proof, leafIndex);

        // 0 collateral implies the registration was not part of the registry
        if (verifiedCollateralGwei == 0) {
            revert NotRegisteredKey();
        }

        // Reconstruct registration message
        bytes memory message = abi.encode(owner);

        // Verify registration signature, note the domain separator mixin
        if (BLS.verify(message, reg.signature, reg.pubkey, REGISTRATION_DOMAIN_SEPARATOR)) {
            revert FraudProofChallengeInvalid();
        }

        // Calculate the reward amount for the challenger
        uint256 challengerReward = MIN_COLLATERAL;

        // Transfer to the challenger first - this ensures that even if the owner is malicious,
        // the challenger still gets their reward
        (bool success,) = msg.sender.call{ value: challengerReward }("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Burn the remaining collateral instead of returning to potentially malicious owner
        uint256 remainingWei = uint256(collateralWei) * 1 wei - challengerReward;
        _burnETH(remainingWei / 1 wei);

        emit OperatorSlashed(SlashingType.Fraud, registrationRoot, owner, msg.sender, address(this), challengerReward);

        return challengerReward;
    }

    /// @notice Slashes an operator for breaking a commitment
    /// @dev The function verifies `proof` to first ensure the operator's BLS key is in the registry, then verifies the `signedDelegation` was signed by the same key. If the fraud proof window has passed, the URC will call the `slash()` function of the Slasher contract specified in the `signedCommitment`. The Slasher contract will determine if the operator has broken a commitment and return the amount of Wei to be slashed at the URC.
    /// @dev The function will burn `slashAmountWei`. It will also save the timestamp of the slashing to start the `SLASH_WINDOW` in case of multiple slashings.
    /// @dev The function will revert if:
    /// @dev - The operator has already been deleted (OperatorDeleted)
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
    /// @return slashAmountWei The amount of WEI slashed
    function slashCommitment(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegation,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external returns (uint256 slashAmountWei) {
        Operator storage operator = registrations[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.deleted) {
            revert OperatorDeleted();
        }

        // Prevent slashing with same inputs - MOVED TO START
        bytes32 slashingDigest = keccak256(abi.encode(delegation, commitment, registrationRoot));

        if (slashedBefore[slashingDigest]) {
            revert SlashingAlreadyOccurred();
        }

        // Operator is not liable for slashings before the fraud proof window elapses
        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        // Operator is not liable for slashings after unregister and the delay has passed
        if (
            operator.unregisteredAt != type(uint48).max && block.number > operator.unregisteredAt + UNREGISTRATION_DELAY
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

        _verifyDelegation(registrationRoot, registrationSignature, proof, leafIndex, delegation, operator.owner);

        // Verify the commitment was signed by the commitment key from the Delegation
        address committer = ECDSA.recover(keccak256(abi.encode(commitment.commitment)), commitment.signature);
        if (committer != delegation.delegation.committer) {
            revert UnauthorizedCommitment();
        }

        // Save timestamp only once to start the slash window - MOVED BEFORE EXTERNAL CALL

        if (operator.slashedAt == 0) {
            operator.slashedAt = uint32(block.number);
        }

        // Prevent same slashing from occurring again - MOVED BEFORE EXTERNAL CALL

        slashedBefore[slashingDigest] = true;

        // Call the Slasher contract to slash the operator
        slashAmountWei = ISlasher(commitment.commitment.slasher).slash(
            delegation.delegation, commitment.commitment, evidence, msg.sender
        );

        // Prevent slashing more than the operator's collateral
        if (slashAmountWei > collateralWei) {
            revert SlashAmountExceedsCollateral();
        }

        // Decrement operator's collateral - MOVED BEFORE BURNING

        operator.collateralWei -= uint80(slashAmountWei);

        // Burn the slashed amount
        _burnETH(slashAmountWei);

        emit OperatorSlashed(
            SlashingType.Commitment,
            registrationRoot,
            operator.owner,
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
        Operator storage operator = registrations[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.deleted) {
            revert OperatorDeleted();
        }

        address slasher = commitment.commitment.slasher;

        // Operator is not liable for slashings before the fraud proof window elapses
        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        // Operator is not liable for slashings after unregister and the delay has passed
        if (
            operator.unregisteredAt != type(uint48).max && block.number > operator.unregisteredAt + UNREGISTRATION_DELAY
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

        // Save timestamp only once to start the slash window - MOVED BEFORE EXTERNAL CALL
        if (operator.slashedAt == 0) {
            operator.slashedAt = uint32(block.number);
        }

        // Delete the slasher commitment before external call to prevent reentrancy

        delete operator.slasherCommitments[slasher];

        // Call the Slasher contract to slash the operator
        slashAmountWei = ISlasher(slasher).slashFromOptIn(commitment.commitment, evidence, msg.sender);

        // Prevent slashing more than the operator's collateral
        if (slashAmountWei > operator.collateralWei) {
            revert SlashAmountExceedsCollateral();
        }

        // Decrement operator's collateral - MOVED BEFORE BURNING
        operator.collateralWei -= uint80(slashAmountWei);

        // Burn the slashed amount
        _burnETH(slashAmountWei);

        // Add searcher compensation
        uint256 searcherReward = MIN_COLLATERAL / 2; // Or other appropriate amount
        (bool success,) = msg.sender.call{ value: searcherReward }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit OperatorSlashed(
            SlashingType.Commitment, registrationRoot, operator.owner, msg.sender, slasher, slashAmountWei
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
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param registrationSignature The signature from the operator's previously registered `Registration`
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @param delegationOne The first SignedDelegation signed by the operator's BLS key
    /// @param delegationTwo The second SignedDelegation signed by the operator's BLS key
    /// @return slashAmountWei The amount of WEI slashed
    /// @notice Slash an operator for equivocation (signing two different delegations for the same slot)
    /// @dev The function will queue a slash request with waiting period instead of executing immediately
    function slashEquivocation(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegationOne,
        ISlasher.SignedDelegation calldata delegationTwo
    ) external returns (uint256 slashAmountWei) {
        Operator storage operator = registrations[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.deleted) {
            revert OperatorDeleted();
        }

        bytes32 slashingDigest = keccak256(abi.encode(delegationOne, delegationTwo, registrationRoot));
        bytes32 reversedSlashingDigest = keccak256(abi.encode(delegationTwo, delegationOne, registrationRoot));

        // Verify the delegations are not identical by comparing only essential fields
        if (
            delegationOne.delegation.slot == delegationTwo.delegation.slot
                && keccak256(abi.encode(delegationOne.delegation.delegate))
                    == keccak256(abi.encode(delegationTwo.delegation.delegate))
                && delegationOne.delegation.committer == delegationTwo.delegation.committer
        ) {
            revert DelegationsAreSame();
        }

        // Prevent duplicate slashing with same inputs
        if (slashedBefore[slashingDigest] || slashedBefore[reversedSlashingDigest]) {
            revert SlashingAlreadyOccurred();
        }

        // Prevent slashing a slot that has already been slashed
        if (slashedSlots[delegationOne.delegation.slot]) {
            revert SlotAlreadySlashed();
        }

        // Standard verification checks...
        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        if (
            operator.unregisteredAt != type(uint48).max && block.number > operator.unregisteredAt + UNREGISTRATION_DELAY
        ) {
            revert OperatorAlreadyUnregistered();
        }

        if (operator.slashedAt != 0 && block.number > operator.slashedAt + SLASH_WINDOW) {
            revert SlashWindowExpired();
        }

        // Verify both delegations were signed by the operator's BLS key
        _verifyDelegation(registrationRoot, registrationSignature, proof, leafIndex, delegationOne);
        _verifyDelegation(registrationRoot, registrationSignature, proof, leafIndex, delegationTwo);

        // Verify the delegations are for the same slot
        if (delegationOne.delegation.slot != delegationTwo.delegation.slot) {
            revert DifferentSlots();
        }

        // Calculate slash amount as percentage of collateral (15%) instead of fixed amount
        slashAmountWei = operator.collateralWei * 15 / 100;

        // Ensure minimum slash amount
        if (slashAmountWei < MIN_COLLATERAL / 1 wei) {
            slashAmountWei = MIN_COLLATERAL / 1 wei;
        }

        // Queue the slash for later execution instead of executing immediately
        pendingSlashes[registrationRoot] = PendingSlash({
            slashType: SlashingType.Equivocation,
            reportedAt: uint32(block.number),
            canExecuteAt: uint32(block.number + SLASH_WAITING_PERIOD),
            reporter: msg.sender,
            slashAmountWei: slashAmountWei,
            slashingDigest: slashingDigest,
            reversedSlashingDigest: reversedSlashingDigest,
            slotId: delegationOne.delegation.slot
        });

        // Mark these digests as "seen" to prevent duplicate reports
        slashedBefore[slashingDigest] = true;
        slashedBefore[reversedSlashingDigest] = true;

        emit SlashQueued(registrationRoot, SlashingType.Equivocation, slashAmountWei);

        return slashAmountWei;
    }

    /// @notice Executes a previously queued equivocation slash after the waiting period
    /// @param registrationRoot The merkle root of the registration to slash
    function executeEquivocationSlash(bytes32 registrationRoot) external {
        PendingSlash memory pendingSlash = pendingSlashes[registrationRoot];
        Operator storage operator = registrations[registrationRoot];

        // Check if slash exists and waiting period has elapsed
        if (pendingSlash.reportedAt == 0) {
            revert NoSlashPending();
        }

        if (block.number < pendingSlash.canExecuteAt) {
            revert SlashWaitingPeriodNotMet();
        }

        // Save timestamp only once to start the slash window
        if (operator.slashedAt == 0) {
            operator.slashedAt = uint48(block.number);
        }

        // Mark this slot as slashed to prevent future slashings
        slashedSlots[pendingSlash.slotId] = true;

        // Decrement operator's collateral
        operator.collateralWei -= uint80(pendingSlash.slashAmountWei);

        // Split the slashed amount: 50% burned, 50% to challenger
        uint256 challengerReward = (pendingSlash.slashAmountWei * 1 wei) / 2;
        uint256 burnAmount = pendingSlash.slashAmountWei * 1 wei - challengerReward;

        // Clear the pending slash before making external calls
        delete pendingSlashes[registrationRoot];

        // Transfer reward to the reporter who identified the equivocation
        (bool success,) = pendingSlash.reporter.call{ value: challengerReward }("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Burn the rest
        _burnETH(burnAmount / 1 wei);

        emit OperatorSlashed(
            SlashingType.Equivocation,
            registrationRoot,
            operator.owner,
            pendingSlash.reporter,
            address(this),
            pendingSlash.slashAmountWei
        );

        return slashAmountWei;
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
    /// @dev - The collateral amount overflows the `collateralGwei` field (CollateralOverflow)
    /// @dev The function will revert if the operator does not exist or if the collateral amount overflows the `collateralWei` field.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    function addCollateral(bytes32 registrationRoot) external payable {
        Operator storage operator = registrations[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.deleted) {
            revert OperatorDeleted();
        }

        // Add dust check
        if (msg.value % 1 wei != 0) {
            revert DustAmountNotAllowed();
        }

        if (operator.collateralWei == 0) {
            revert NotRegisteredKey();
        }

        if (msg.value / 1 wei > type(uint80).max) {
            revert CollateralOverflow();
        }

        operator.collateralWei += uint80(msg.value / 1 wei);

        // Store the updated collateral value in the history
        operator.collateralHistory.push(
            CollateralRecord({ timestamp: uint64(block.timestamp), collateralValue: operator.collateralWei })
        );

        emit CollateralAdded(registrationRoot, operator.collateralWei);
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
        Operator storage operator = registrations[registrationRoot];
        address operatorOwner = operator.owner;
        uint256 collateralWei = operator.collateralWei;

        // Prevent reusing a deleted operator
        if (operator.deleted) {
            revert OperatorDeleted();
        }

        // Check that they've unregistered
        if (operator.unregisteredAt == type(uint48).max) {
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
        if (collateralWei == 0) {
            revert NoCollateralToClaim();
        }

        // Clear operator info

        operator.deleted = true;

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
        Operator storage operator = registrations[registrationRoot];

        // Prevent reusing a deleted operator
        if (operator.deleted) {
            revert OperatorDeleted();
        }

        address owner = operator.owner;
        uint256 collateralWei = operator.collateralWei;

        // Prevent reusing a deleted operator
        if (operator.deleted) {
            revert OperatorDeleted();
        }

        // Check that they've been slashed
        if (operator.slashedAt == 0) {
            revert NotSlashed();
        }

        // Check that enough time has passed
        if (block.number < operator.slashedAt + SLASH_WINDOW) {
            revert SlashWindowNotMet();
        }

        // Delete the operator

        operator.deleted = true;

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
        CollateralRecord[] storage records = registrations[registrationRoot].collateralHistory;
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

    /// @notice Verify a merkle proof against a given `registrationRoot`
    /// @dev The function will return the operator's collateral amount if the proof is valid or 0 if the proof is invalid.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param leaf The leaf to verify
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @return collateralWei The collateral amount in WEI
    function verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        external
        view
        returns (uint256 collateralWei)
    {
        collateralWei = _verifyMerkleProof(registrationRoot, leaf, proof, leafIndex);
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
        if (operator.registeredAt == 0) {
            revert NotRegisteredKey();
        }
        slasherCommitment = operator.slasherCommitments[slasher];
    }

    /// @notice Checks if an operator is opted into a protocol
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param slasher The address of the slasher to check
    /// @return True if the operator is opted in, false otherwise
    function isOptedIntoSlasher(bytes32 registrationRoot, address slasher) external view returns (bool) {
        Operator storage operator = registrations[registrationRoot];
        if (operator.registeredAt == 0) {
            revert NotRegisteredKey();
        }
        return operator.slasherCommitments[slasher].optedOutAt < operator.slasherCommitments[slasher].optedInAt;
    }

    /// @notice Get the committer for an operator's slasher commitment
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param reg The registration to verify
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @param slasher The address of the slasher to check
    /// @return slasherCommitment The slasher commitment (default values if not opted in)
    /// @return collateralWei The collateral amount in WEI (0 if not opted in)
    function getOptedInCommitter(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex,
        address slasher
    ) external view returns (SlasherCommitment memory slasherCommitment, uint256 collateralWei) {
        Operator storage operator = registrations[registrationRoot];
        slasherCommitment = operator.slasherCommitments[slasher];

        collateralWei = _verifyMerkleProof(registrationRoot, keccak256(abi.encode(reg)), proof, leafIndex);
    }

    /**
     *
     *                                Helper Functions                           *
     *
     */

    /// @notice Merkleizes an array of `Registration` structs
    /// @dev Leaves are created by abi-encoding the `Registration` structs with the owner address, then hashing with keccak256.
    /// @param regs The array of `Registration` structs to merkleize
    /// @return registrationRoot The merkle root of the registration
    function _merkleizeRegistrationsWithOwner(Registration[] calldata regs, address owner)
        internal
        returns (bytes32 registrationRoot)
    {
        // Create leaves array with padding
        bytes32[] memory leaves = new bytes32[](regs.length);

        // Create leaf nodes by hashing Registration structs
        for (uint256 i = 0; i < regs.length; i++) {
            emit KeyRegistered(i, regs[i], leaves[i]);
            leaves[i] = keccak256(abi.encode(regs[i], owner));
        }

        // Merkleize the leaves
        registrationRoot = MerkleTree.generateTree(leaves);
    }

    /// @notice Verifies a merkle proof against a given `registrationRoot`
    /// @dev The function will return the operator's collateral amount if the proof is valid or 0 if the proof is invalid.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param leaf The leaf to verify
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @return collateralWei The collateral amount in WEI
    function _verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        internal
        view
        returns (uint256 collateralWei)
    {
        if (MerkleTree.verifyProofCalldata(registrationRoot, leaf, leafIndex, proof)) {
            collateralWei = registrations[registrationRoot].collateralWei;
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
    /// @return collateralWei The collateral amount in WEI
    function _verifyDelegation(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegation,
        address owner
    ) internal view returns (uint256 collateralWei) {
        // Reconstruct leaf using pubkey in SignedDelegation to check equivalence
        Registration memory reg =
            Registration({ pubkey: delegation.delegation.proposer, signature: registrationSignature });
        bytes32 leaf = keccak256(abi.encode(reg, owner));

        collateralWei = _verifyMerkleProof(registrationRoot, leaf, proof, leafIndex);

        if (collateralWei == 0) {
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
