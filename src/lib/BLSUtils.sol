// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "solady/utils/ext/ithaca/BLS.sol";
// Credit: https://github.com/paradigmxyz/forge-alphanet/blob/main/src/sign/BLS.sol

/// @title BLS
/// @notice Utility functions to built on top of the Solady BLS library.
library BLSUtils {
    using BLS for *;

    /// @notice G1MUL operation
    /// @param point G1 point
    /// @param scalar Scalar to multiply the point by
    /// @return result Resulted G1 point
    function mul(BLS.G1Point memory point, bytes32 scalar) internal view returns (BLS.G1Point memory result) {
        BLS.G1Point[] memory points = new BLS.G1Point[](1);
        bytes32[] memory scalars = new bytes32[](1);

        points[0] = point;
        scalars[0] = scalar;

        return BLS.msm(points, scalars);
    }

    /// @notice G2MUL operation
    /// @param point G2 point
    /// @param scalar Scalar to multiply the point by
    /// @return result Resulted G2 point
    function mul(BLS.G2Point memory point, bytes32 scalar) internal view returns (BLS.G2Point memory result) {
        BLS.G2Point[] memory points = new BLS.G2Point[](1);
        bytes32[] memory scalars = new bytes32[](1);

        points[0] = point;
        scalars[0] = scalar;

        return BLS.msm(points, scalars);
    }

    function G1_GENERATOR() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            _u(31827880280837800241567138048534752271),
            _u(88385725958748408079899006800036250932223001591707578097800747617502997169851),
            _u(11568204302792691131076548377920244452),
            _u(114417265404584670498511149331300188430316142484413708742216858159411894806497)
        );
    }

    function NEGATED_G1_GENERATOR() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            _u(31827880280837800241567138048534752271),
            _u(88385725958748408079899006800036250932223001591707578097800747617502997169851),
            _u(22997279242622214937712647648895181298),
            _u(46816884707101390882112958134453447585552332943769894357249934112654335001290)
        );
    }

    function _u(uint256 x) internal pure returns (bytes32) {
        return bytes32(x);
    }

    /// @dev Referenced from https://eips.ethereum.org/EIPS/eip-2537#curve-parameters
    function baseFieldModulus() internal pure returns (uint256[2] memory) {
        return [
            0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7,
            0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
        ];
    }

    /**
     * @notice Negates a G1 point, by reflecting it over the x-axis
     * @dev Adapted from https://github.com/NethermindEth/Taiko-Preconf-AVS/blob/004d407105578a83c4815e7ec2c55ec467b9ed3f/SmartContracts/src/libraries/BLS12381.sol#L124
     * @dev Assumes that the Y coordinate is always less than the field modulus
     * @param point The G1 point to negate
     */
    function negate(BLS.G1Point memory point) internal pure returns (BLS.G1Point memory) {
        uint256[2] memory fieldModulus = baseFieldModulus();
        uint256[2] memory yNeg;

        // Perform word-wise elementary subtraction
        if (fieldModulus[1] < uint256(point.y_b)) {
            yNeg[1] = type(uint256).max - (uint256(point.y_b) - fieldModulus[1]) + 1;
            fieldModulus[0] -= 1; // borrow
        } else {
            yNeg[1] = fieldModulus[1] - uint256(point.y_b);
        }
        yNeg[0] = fieldModulus[0] - uint256(point.y_a);

        return BLS.G1Point({ x_a: point.x_a, x_b: point.x_b, y_a: _u(yNeg[0]), y_b: _u(yNeg[1]) });
    }

    /**
     * @notice Returns true if `a` is lexicographically greater than `b`
     * @dev Adapted from https://github.com/NethermindEth/Taiko-Preconf-AVS/blob/004d407105578a83c4815e7ec2c55ec467b9ed3f/SmartContracts/src/libraries/BLS12381.sol#L124
     * @dev It makes the comparison bit-wise.
     * This functions also assumes that the passed values are 48-byte long BLS pub keys that have
     * 16 functional bytes in the first word, and 32 bytes in the second.
     */
    // function _greaterThan(uint256[2] memory a, uint256[2] memory b) internal pure returns (bool) {
    function _greaterThan(BLS.Fp memory a, BLS.Fp memory b) internal pure returns (bool) {
        uint256 wordA;
        uint256 wordB;
        uint256 mask;

        // Only compare the unequal words
        if (a.a == b.a) {
            wordA = uint256(a.b);
            wordB = uint256(b.b);
            mask = 1 << 255;
        } else {
            wordA = uint256(a.a);
            wordB = uint256(b.a);
            mask = 1 << 127; // Only check for lower 16 bytes in the first word
        }

        // We may safely set the control value to be less than 256 since it is guaranteed that the
        // the loop returns if the first words are different.
        for (uint256 i; i < 256; ++i) {
            uint256 x = wordA & mask;
            uint256 y = wordB & mask;

            if (x == 0 && y != 0) return false;
            if (x != 0 && y == 0) return true;

            mask = mask >> 1;
        }

        return false;
    }

    /// @notice Converts a private key to a public key by multiplying the generator point with the private key
    /// @param privateKey The private key to convert
    /// @return The public key
    function toPublicKey(uint256 privateKey) internal view returns (BLS.G1Point memory) {
        return mul(G1_GENERATOR(), _u(privateKey));
    }

    /// @notice Converts a message to a G2 point
    /// @param message Arbitrarylength byte string to be hashed with the domainSeparator
    /// @param domainSeparator The domain separation tag
    /// @return A point in G2
    function toMessagePoint(bytes memory message, bytes memory domainSeparator)
        internal
        view
        returns (BLS.G2Point memory)
    {
        return BLS.toG2(
            BLS.Fp2({ c0_a: 0, c0_b: 0, c1_a: 0, c1_b: keccak256(abi.encodePacked(domainSeparator, message)) })
        );
    }

    /// @notice Signs a message
    /// @param message Arbitrarylength byte string to be hashed with the domainSeparator
    /// @param privateKey The private key to sign with
    /// @param domainSeparator The domain separation tag
    /// @return A signature in G2
    function sign(bytes memory message, uint256 privateKey, bytes memory domainSeparator)
        internal
        view
        returns (BLS.G2Point memory)
    {
        return mul(toMessagePoint(message, domainSeparator), _u(privateKey));
    }

    /// @notice Verifies a signature
    /// @param message Arbitrarylength byte string to be hashed
    /// @param signature The signature to verify
    /// @param publicKey The public key to verify against
    /// @param domainSeparator The domain separation tag
    /// @return True if the signature is valid, false otherwise
    function verify(
        bytes memory message,
        BLS.G2Point memory signature,
        BLS.G1Point memory publicKey,
        bytes memory domainSeparator
    ) public view returns (bool) {
        // Hash the message bytes into a G2 point
        BLS.G2Point memory messagePoint = toMessagePoint(message, domainSeparator);

        // Invoke the BLS.pairing check to verify the signature.
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = NEGATED_G1_GENERATOR();
        g1Points[1] = publicKey;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = signature;
        g2Points[1] = messagePoint;

        return BLS.pairing(g1Points, g2Points);
    }

    /**
     * @notice Returns a BLS.G1Point in the compressed form
     * @dev Adapted from https://github.com/NethermindEth/Taiko-Preconf-AVS/blob/004d407105578a83c4815e7ec2c55ec467b9ed3f/SmartContracts/src/libraries/BLS12381.sol#L124
     * @dev Originally based on https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/BLS.pairing/src/bls12_381/README.md#serialization
     * @param point The G1 point to compress
     */
    function compress(BLS.G1Point memory point) internal pure returns (BLS.Fp memory) {
        BLS.Fp memory r = BLS.Fp({ a: point.x_a, b: point.x_b });

        // Set the first MSB
        r.a = bytes32(uint256(r.a) | (1 << 127));

        // Second MSB is left to be 0 since we are assuming that no infinity points are involved

        // Set the third MSB if point.y is lexicographically larger than the y in negated point
        BLS.G1Point memory negatedPoint = negate(point);
        if (_greaterThan(BLS.Fp({ a: point.y_a, b: point.y_b }), BLS.Fp({ a: negatedPoint.y_a, b: negatedPoint.y_b })))
        {
            r.a = bytes32(uint256(r.a) | (1 << 125));
        }

        return r;
    }
}
