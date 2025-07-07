// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "solady/utils/ext/ithaca/BLS.sol";

interface ISlasher {
    /// @notice A Delegation message from a proposer's BLS key to a delegate's BLS and ECDSA key
    struct Delegation {
        /// The proposer's BLS public key
        BLS.G1Point proposer;
        /// The delegate's BLS public key for Constraints API
        BLS.G1Point delegate;
        /// The address of the delegate's ECDSA key for signing commitments
        address committer;
        /// The slot number the delegation is valid for
        uint64 slot;
        /// Arbitrary metadata reserved for future use
        bytes metadata;
    }

    /// @notice A delegation message signed by a proposer's BLS key
    struct SignedDelegation {
        /// The delegation message
        Delegation delegation;
        /// The signature of the delegation message
        BLS.G2Point signature;
    }

    /// @notice A Commitment message binding an opaque payload to a slasher contract
    struct Commitment {
        /// The type of commitment
        uint64 commitmentType;
        /// The payload of the commitment
        bytes payload;
        /// The address of the slasher contract
        address slasher;
    }

    /// @notice A commitment message signed by a delegate's ECDSA key
    struct SignedCommitment {
        /// The commitment message
        Commitment commitment;
        /// The signature of the commitment message
        bytes signature;
    }

    /// @notice Slash a proposer's BLS key for a given delegation and a commitment
    /// @dev The URC will call this function to slash a registered operator if supplied with valid evidence
    /// @dev Note that the `delegation` may be optional in cases where the slashing is due
    /// @dev to a commitment that is not associated with an off-chain delegation
    /// @dev Note when implementing this function, if the `evidence` is unused, the contract should assert it is empty to prevent replaying slashings on the URC.
    /// @dev Note when implementing this function, the contract should not allow permutations of the `evidence` to result in the same slashing result to prevent replaying slashings on the URC.
    /// @param delegation The delegation message
    /// @param commitment The commitment message
    /// @param committer The address of the committer
    /// @param evidence Arbitrary evidence for the slashing
    /// @param challenger The address of the challenger
    /// @return slashAmountWei The amount of WEI slashed
    function slash(
        Delegation calldata delegation,
        Commitment calldata commitment,
        address committer,
        bytes calldata evidence,
        address challenger
    ) external returns (uint256 slashAmountWei);
}
