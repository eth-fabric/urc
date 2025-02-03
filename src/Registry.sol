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

    /// @notice Mapping to track opt-in and opt-out status for proposer commitment protocols
    mapping(bytes32 => SlasherCommitment) public slasherCommitments;

    // Constants
    uint256 public constant MIN_COLLATERAL = 0.1 ether;
    uint256 public constant MIN_UNREGISTRATION_DELAY = 64; // Two epochs
    uint256 public constant FRAUD_PROOF_WINDOW = 7200; // 1 day
    uint32 public constant SLASH_WINDOW = 7200; // 1 day
    uint32 public constant OPT_IN_DELAY = 7200; // 1 day
    address internal constant BURNER_ADDRESS = address(0x0000000000000000000000000000000000000000);
    bytes public constant DOMAIN_SEPARATOR = "0x00435255"; // "URC" in little endian
    bytes public constant DELEGATION_DOMAIN_SEPARATOR = "0x0044656c"; // "Del" in little endian

    /// @notice Batch registers an operator's BLS keys and collateral to the registry
    /// @dev Registration signatures are optimistically verified. They are expected to be signed with the `DOMAIN_SEPARATOR` mixin.
    /// @dev The function will merkleize the supplied `regs` and map the registration root to an Operator struct.
    /// @dev The function will revert if the operator has already registered the same `regs`, if they sent less than `MIN_COLLATERAL`, if the unregistration delay is less than `MIN_UNREGISTRATION_DELAY`, or if the registration root is invalid.
    /// @param regs The BLS keys to register
    /// @param owner The authorized address to perform actions on behalf of the operator
    /// @param unregistrationDelay The number of blocks before the operator can be unregistered
    /// @return registrationRoot The merkle root of the registration
    function register(Registration[] calldata regs, address owner, uint16 unregistrationDelay)
        external
        payable
        returns (bytes32 registrationRoot)
    {
        if (msg.value < MIN_COLLATERAL) {
            revert InsufficientCollateral();
        }

        if (unregistrationDelay < MIN_UNREGISTRATION_DELAY) {
            revert UnregistrationDelayTooShort();
        }

        registrationRoot = _merkleizeRegistrations(regs);

        if (registrationRoot == bytes32(0)) {
            revert InvalidRegistrationRoot();
        }

        if (registrations[registrationRoot].registeredAt != 0) {
            revert OperatorAlreadyRegistered();
        }

        registrations[registrationRoot] = Operator({
            owner: owner,
            collateralGwei: uint56(msg.value / 1 gwei),
            registeredAt: uint32(block.number),
            unregistrationDelay: unregistrationDelay,
            unregisteredAt: type(uint32).max,
            slashedAt: 0
        });

        emit OperatorRegistered(registrationRoot, msg.value, unregistrationDelay);
    }

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

    /// @notice Slash an operator for submitting a fraudulent `Registration` in the register() function
    /// @dev To save BLS verification gas costs, the URC optimistically accepts registration signatures. This function allows a challenger to slash the operator by executing the BLS verification to prove the registration is fraudulent.
    /// @dev The function will delete the operator's registration, transfer `MIN_COLLATERAL` to the caller, and return any remaining funds to the operator's withdrawal address.
    /// @dev The function will revert if the operator has already unregistered, if the operator has not registered, if the fraud proof window has expired, or if the proof is invalid.
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
        address operatorOwner = operator.owner;

        if (block.number > operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowExpired();
        }

        uint256 collateralGwei = _verifyMerkleProof(registrationRoot, keccak256(abi.encode(reg)), proof, leafIndex);

        if (collateralGwei == 0) {
            revert NotRegisteredKey();
        }

        // Reconstruct registration message
        bytes memory message = abi.encodePacked(operatorOwner, operator.unregistrationDelay);

        // Verify registration signature
        if (BLS.verify(message, reg.signature, reg.pubkey, DOMAIN_SEPARATOR)) {
            revert FraudProofChallengeInvalid();
        }

        // Delete the operator
        delete registrations[registrationRoot];

        // Calculate the amount to transfer to challenger and return to operator
        uint256 remainingWei = uint256(collateralGwei) * 1 gwei - MIN_COLLATERAL;

        // Transfer to the challenger
        (bool success,) = msg.sender.call{ value: MIN_COLLATERAL }("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Return any remaining funds to Operator
        (success,) = operatorOwner.call{ value: remainingWei }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit RegistrationSlashed(registrationRoot, msg.sender, operatorOwner, reg);

        return MIN_COLLATERAL;
    }

    /// @notice Starts the unregistration process for an operator
    /// @dev The function will revert if the operator has already unregistered, if the operator has not registered, or if the caller is not the operator's withdrawal address.
    /// @dev The function will mark the `unregisteredAt` timestamp in the Operator struct. The operator can claim their collateral after the `unregistrationDelay` more blocks have passed.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    function unregister(bytes32 registrationRoot) external {
        Operator storage operator = registrations[registrationRoot];

        if (operator.owner != msg.sender) {
            revert WrongOperator();
        }

        // Check that they haven't already unregistered
        if (operator.unregisteredAt != type(uint32).max) {
            revert AlreadyUnregistered();
        }

        // Set unregistration timestamp
        operator.unregisteredAt = uint32(block.number);

        emit OperatorUnregistered(registrationRoot, operator.unregisteredAt);
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
        if (block.number < operator.unregisteredAt + operator.unregistrationDelay) {
            revert UnregistrationDelayNotMet();
        }

        // Check there's collateral to claim
        if (collateralGwei == 0) {
            revert NoCollateralToClaim();
        }

        uint256 amountToReturn = collateralGwei * 1 gwei;

        // Clear operator info
        delete registrations[registrationRoot];

        // Transfer to operator
        (bool success,) = operatorOwner.call{ value: amountToReturn }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit CollateralClaimed(registrationRoot, collateralGwei);
    }

    /// @notice Opts an operator into a proposer commtiment protocol via Slasher contract
    /// @dev The function will revert if the operator has not registered or if the caller is not the operator's owner
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param slasher The address of the Slasher contract to opt into
    /// @param committer The address of the key used for commitments
    function optInToSlasher(bytes32 registrationRoot, address slasher, address committer) external {
        Operator storage operator = registrations[registrationRoot];

        if (operator.owner != msg.sender) {
            revert WrongOperator();
        }

        // Create a unique identifier for the slasher commitment
        bytes32 slasherCommitmentId = keccak256(abi.encode(registrationRoot, slasher));

        // Cache the SlasherCommitment struct
        SlasherCommitment storage slasherCommitment = slasherCommitments[slasherCommitmentId];

        // Check if already opted in
        if (slasherCommitment.optedOutAt < slasherCommitment.optedInAt) {
            revert AlreadyOptedIn();
        }

        // If previously opted out, enforce a delay before allowing new opt-in
        if (slasherCommitment.optedOutAt != 0 && block.timestamp < slasherCommitment.optedOutAt + OPT_IN_DELAY) {
            revert OptInDelayNotMet();
        }

        slasherCommitment.optedInAt = uint64(block.number);
        slasherCommitment.optedOutAt = 0;
        slasherCommitment.committer = committer;

        emit OperatorOptedIn(registrationRoot, slasher, committer, slasherCommitment.optedInAt);
    }

    /// @notice Opts out of a protocol for an operator
    /// @dev The function will revert if the operator has not registered, if the caller is not the operator's owner, or if the operator is not opted into the protocol
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param slasher The address of the Slasher contract to opt out of
    function optOutOfSlasher(bytes32 registrationRoot, address slasher) external {
        Operator storage operator = registrations[registrationRoot];

        if (operator.owner != msg.sender) {
            revert WrongOperator();
        }

        bytes32 slasherCommitmentId = keccak256(abi.encode(registrationRoot, slasher));

        // Cache the SlasherCommitment struct
        SlasherCommitment storage slasherCommitment = slasherCommitments[slasherCommitmentId];

        // Check if already opted out or never opted in
        if (slasherCommitment.optedOutAt >= slasherCommitment.optedInAt) {
            revert NotOptedIn();
        }

        slasherCommitment.optedOutAt = uint64(block.number);

        emit OperatorOptedOut(registrationRoot, slasher, slasherCommitment.optedOutAt);
    }

    /// @notice Slashes an operator for breaking a commitment
    /// @dev The function verifies `proof` to first ensure the operator's key is in the registry, then verifies the `signedDelegation` was signed by the key. If the fraud proof window has passed, the URC will call the `slash()` function of the Slasher contract specified in the `signedDelegation`. The Slasher contract will determine if the operator has broken a commitment and return the amount of GWEI to be slashed at the URC.
    /// @dev The function will burn `slashAmountGwei` and transfer `rewardAmountGwei` to the caller. It will also save the timestamp of the slashing to start the `SLASH_WINDOW` in case of multiple slashings.
    /// @dev The function will revert if the operator has not registered, if the fraud proof window has not passed, if the operator has already unregistered, if the proof is invalid, or if the slash window has expired.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param registrationSignature The signature from the operator's previously registered `Registration`
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @param delegation The SignedDelegation signed by the operator's BLS key
    /// @param commitment The SignedCommitment signed by the delegate's ECDSA key
    /// @param evidence Arbitrary evidence to slash the operator, required by the Slasher contract
    /// @return slashAmountGwei The amount of GWEI slashed
    /// @return rewardAmountGwei The amount of GWEI rewarded to the caller
    function slashCommitment(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata delegation,
        ISlasher.SignedCommitment calldata commitment,
        bytes calldata evidence
    ) external returns (uint256 slashAmountGwei, uint256 rewardAmountGwei) {
        Operator storage operator = registrations[registrationRoot];

        bytes32 slashingDigest = keccak256(abi.encode(delegation, commitment, registrationRoot));

        if (slashedBefore[slashingDigest]) {
            revert SlashingAlreadyOccurred();
        }

        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        if (
            operator.unregisteredAt != type(uint32).max
                && block.number > operator.unregisteredAt + operator.unregistrationDelay
        ) {
            revert OperatorAlreadyUnregistered();
        }

        if (operator.slashedAt != 0 && block.number > operator.slashedAt + SLASH_WINDOW) {
            revert SlashWindowExpired();
        }

        uint256 collateralGwei =
            _verifyDelegation(registrationRoot, registrationSignature, proof, leafIndex, delegation);

        // Verify the commitment was signed by the commitment key from the Delegation
        address committer = ECDSA.recover(keccak256(abi.encode(commitment.commitment)), commitment.signature);

        if (committer != delegation.delegation.committer) {
            revert UnauthorizedCommitment();
        }

        (slashAmountGwei, rewardAmountGwei) =
            _executeSlash(delegation.delegation, commitment.commitment, evidence, collateralGwei);

        // Reward challenger + burn Ether
        _executeSlashingTransfers(slashAmountGwei, rewardAmountGwei);

        // Save timestamp only once
        if (operator.slashedAt == 0) {
            operator.slashedAt = uint32(block.number);
        }

        // Decrement operator's collateral
        operator.collateralGwei -= uint56(slashAmountGwei + rewardAmountGwei);

        // Prevent same slashing from occurring again
        slashedBefore[slashingDigest] = true;

        emit OperatorSlashed(registrationRoot, slashAmountGwei, rewardAmountGwei, delegation.delegation.proposer);
    }

    /// @notice Slash an operator for equivocation (signing two different delegations for the same slot)
    /// @dev The function will slash the operator's collateral and transfer `MIN_COLLATERAL` to the caller
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
    ) external {
        Operator storage operator = registrations[registrationRoot];

        bytes32 slashingDigest = keccak256(abi.encode(delegationOne, delegationTwo, registrationRoot));

        // verify the delegations are not the same
        if (keccak256(abi.encode(delegationOne)) == keccak256(abi.encode(delegationTwo))) {
            revert DelegationsAreSame();
        }

        if (slashedBefore[slashingDigest]) {
            revert SlashingAlreadyOccurred();
        }

        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        if (
            operator.unregisteredAt != type(uint32).max
                && block.number > operator.unregisteredAt + operator.unregistrationDelay
        ) {
            revert OperatorAlreadyUnregistered();
        }

        if (operator.slashedAt != 0 && block.number > operator.slashedAt + SLASH_WINDOW) {
            revert SlashWindowExpired();
        }

        // verify both delegations
        uint256 collateralGweiOne =
            _verifyDelegation(registrationRoot, registrationSignature, proof, leafIndex, delegationOne);
        uint256 collateralGweiTwo =
            _verifyDelegation(registrationRoot, registrationSignature, proof, leafIndex, delegationTwo);

        // error if either delegation is invalid
        if (collateralGweiOne == 0 || collateralGweiTwo == 0) {
            revert InvalidDelegation();
        }

        // error if the delegations are for different slots
        if (delegationOne.delegation.slot != delegationTwo.delegation.slot) {
            revert DifferentSlots();
        }

        // Save timestamp only once
        if (operator.slashedAt == 0) {
            operator.slashedAt = uint32(block.number);
        }

        // Decrement operator's collateral
        operator.collateralGwei -= uint56(MIN_COLLATERAL / 1 gwei);

        // Save both permutations of the slashing digest
        slashedBefore[slashingDigest] = true;
        slashedBefore[keccak256(abi.encode(delegationTwo, delegationOne, registrationRoot))] = true;

        // reward the challenger
        (bool success,) = msg.sender.call{ value: MIN_COLLATERAL }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit OperatorEquivocated(registrationRoot, MIN_COLLATERAL, delegationOne.delegation.proposer);
    }

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
        emit CollateralAdded(registrationRoot, operator.collateralGwei);
    }

    function claimSlashedCollateral(bytes32 registrationRoot) external {
        Operator storage operator = registrations[registrationRoot];
        address operatorOwner = operator.owner;
        uint256 collateralGwei = operator.collateralGwei;

        // Check that they've been slashed
        if (operator.slashedAt == 0) {
            revert NotSlashed();
        }

        // Check that enough time has passed
        if (block.number < operator.slashedAt + SLASH_WINDOW) {
            revert SlashWindowNotMet();
        }

        uint256 amountToReturn = collateralGwei * 1 gwei;

        // Clear operator info
        delete registrations[registrationRoot];

        // Transfer to operator
        (bool success,) = operatorOwner.call{ value: amountToReturn }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit CollateralClaimed(registrationRoot, collateralGwei);
    }

    /**
     *
     *                                Internal Functions                           *
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

    /// @notice Executes the slash function of the Slasher contract and returns the amount of GWEI to be slashed
    /// @dev The function will revert if the `slashAmountGwei` is 0, if the `slashAmountGwei` exceeds the operator's collateral, or if the Slasher.slash() function reverts.
    /// @param delegation The SignedDelegation signed by the operator's BLS key
    /// @param commitment The SignedCommitment signed by the delegate's ECDSA key
    /// @param evidence Arbitrary evidence to slash the operator, required by the Slasher contract
    /// @param collateralGwei The operator's collateral amount in GWEI
    /// @return slashAmountGwei The amount of GWEI to be slashed
    function _executeSlash(
        ISlasher.Delegation calldata delegation,
        ISlasher.Commitment calldata commitment,
        bytes calldata evidence,
        uint256 collateralGwei
    ) internal returns (uint256 slashAmountGwei, uint256 rewardAmountGwei) {
        (slashAmountGwei, rewardAmountGwei) =
            ISlasher(commitment.slasher).slash(delegation, commitment, evidence, msg.sender);

        if (slashAmountGwei > collateralGwei) {
            revert SlashAmountExceedsCollateral();
        }
    }

    /// @notice Distributes rewards to the challenger and burns the slash amount
    /// @dev The function will revert if the transfer to the slasher fails or if the rewardAmountGwei is less than `MIN_COLLATERAL`.
    /// @param slashAmountGwei The amount of GWEI to be burned
    /// @param rewardAmountGwei The amount of GWEI to be transferred to the caller
    function _executeSlashingTransfers(uint256 slashAmountGwei, uint256 rewardAmountGwei) internal {
        // Burn the slash amount
        (bool success,) = BURNER_ADDRESS.call{ value: slashAmountGwei * 1 gwei }("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Transfer to the challenger
        (success,) = msg.sender.call{ value: rewardAmountGwei * 1 gwei }("");
        if (!success) {
            revert EthTransferFailed();
        }
    }
}
