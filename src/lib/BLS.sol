// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;
// Credit: https://github.com/paradigmxyz/forge-alphanet/blob/main/src/sign/BLS.sol

/// @title BLS
/// @notice Wrapper functions to abstract low level details of calls to BLS precompiles
///         defined in EIP-2537, see <https://eips.ethereum.org/EIPS/eip-2537>.
/// @dev Precompile addresses come from the BLS addresses submodule in AlphaNet, see
///      <https://github.com/paradigmxyz/alphanet/blob/main/crates/precompile/src/addresses.rs>
/// @notice `hashToCurve` logic is based on <https://github.com/ethyla/bls12-381-hash-to-curve/blob/main/src/HashToCurve.sol>
/// with small modifications including:
///     - Removal of low-level assembly in _modexp to ensure compatibility with EOF which does not support low-level staticcall
///     - Usage of Fp2/G2Point structs defined here for better compatibility with existing methods
library BLS {
    /// @dev A base field element (Fp) is encoded as 64 bytes by performing the
    /// BigEndian encoding of the corresponding (unsigned) integer. Due to the size of p,
    /// the top 16 bytes are always zeroes.
    struct Fp {
        uint256 a;
        uint256 b;
    }

    /// @dev For elements of the quadratic extension field (Fp2), encoding is byte concatenation of
    /// individual encoding of the coefficients totaling in 128 bytes for a total encoding.
    /// c0 + c1 * v
    struct Fp2 {
        Fp c0;
        Fp c1;
    }

    /// @dev Points of G1 and G2 are encoded as byte concatenation of the respective
    /// encodings of the x and y coordinates.
    struct G1Point {
        Fp x;
        Fp y;
    }

    /// @dev Points of G1 and G2 are encoded as byte concatenation of the respective
    /// encodings of the x and y coordinates.
    struct G2Point {
        Fp2 x;
        Fp2 y;
    }

    /// @dev For addition of two points on the BLS12-381 G1 curve,
    address internal constant BLS12_G1ADD = 0x000000000000000000000000000000000000000b;

    /// @dev For multi-scalar multiplication (MSM) on the BLS12-381 G1 curve.
    address internal constant BLS12_G1MSM = 0x000000000000000000000000000000000000000C;

    /// @dev For addition of two points on the BLS12-381 G2 curve.
    address internal constant BLS12_G2ADD = 0x000000000000000000000000000000000000000d;

    /// @dev For multi-scalar multiplication (MSM) on the BLS12-381 G2 curve.
    address internal constant BLS12_G2MSM = 0x000000000000000000000000000000000000000E;

    /// @dev For performing a pairing check on the BLS12-381 curve.
    address internal constant BLS12_PAIRING_CHECK = 0x000000000000000000000000000000000000000F;

    /// @dev For mapping a Fp to a point on the BLS12-381 G1 curve.
    address internal constant BLS12_MAP_FP_TO_G1 = 0x0000000000000000000000000000000000000010;

    /// @dev For mapping a Fp2 to a point on the BLS12-381 G2 curve.
    address internal constant BLS12_MAP_FP2_TO_G2 = 0x0000000000000000000000000000000000000011;

    /// @notice G1ADD operation
    /// @param a First G1 point
    /// @param b Second G1 point
    /// @return result Resulted G1 point
    function G1Add(G1Point memory a, G1Point memory b) internal view returns (G1Point memory result) {
        (bool success, bytes memory output) = address(BLS12_G1ADD).staticcall(abi.encode(a, b));
        require(success, "G1ADD failed");
        return abi.decode(output, (G1Point));
    }

    /// @notice G1MUL operation
    /// @param point G1 point
    /// @param scalar Scalar to multiply the point by
    /// @return result Resulted G1 point
    function G1Mul(G1Point memory point, uint256 scalar) internal view returns (G1Point memory result) {
        (bool success, bytes memory output) = address(BLS12_G1MSM).staticcall(abi.encode(point, scalar));
        require(success, "G1MUL failed");
        return abi.decode(output, (G1Point));
    }

    /// @notice G1MSM operation
    /// @param points Array of G1 points
    /// @param scalars Array of scalars to multiply the points by
    /// @return result Resulted G1 point
    function G1MSM(G1Point[] memory points, uint256[] memory scalars) internal view returns (G1Point memory result) {
        bytes memory input;

        for (uint256 i = 0; i < points.length; i++) {
            input = bytes.concat(input, abi.encode(points[i], scalars[i]));
        }

        (bool success, bytes memory output) = address(BLS12_G1MSM).staticcall(input);
        require(success, "G1MSM failed");
        return abi.decode(output, (G1Point));
    }

    /// @notice G2ADD operation
    /// @param a First G2 point
    /// @param b Second G2 point
    /// @return result Resulted G2 point
    function G2Add(G2Point memory a, G2Point memory b) internal view returns (G2Point memory result) {
        (bool success, bytes memory output) = address(BLS12_G2ADD).staticcall(abi.encode(a, b));
        require(success, "G2ADD failed");
        return abi.decode(output, (G2Point));
    }

    /// @notice G2MUL operation
    /// @param point G2 point
    /// @param scalar Scalar to multiply the point by
    /// @return result Resulted G2 point
    function G2Mul(G2Point memory point, uint256 scalar) internal view returns (G2Point memory result) {
        (bool success, bytes memory output) = address(BLS12_G2MSM).staticcall(abi.encode(point, scalar));
        require(success, "G2MUL failed");
        return abi.decode(output, (G2Point));
    }

    /// @notice G2MSM operation
    /// @param points Array of G2 points
    /// @param scalars Array of scalars to multiply the points by
    /// @return result Resulted G2 point
    function G2MSM(G2Point[] memory points, uint256[] memory scalars) internal view returns (G2Point memory result) {
        bytes memory input;

        for (uint256 i = 0; i < points.length; i++) {
            input = bytes.concat(input, abi.encode(points[i], scalars[i]));
        }

        (bool success, bytes memory output) = address(BLS12_G2MSM).staticcall(input);
        require(success, "G2MSM failed");
        return abi.decode(output, (G2Point));
    }

    /// @notice PAIRING operation
    /// @param g1Points Array of G1 points
    /// @param g2Points Array of G2 points
    /// @return result Returns whether pairing result is equal to the multiplicative identity (1).
    function Pairing(G1Point[] memory g1Points, G2Point[] memory g2Points) internal view returns (bool result) {
        bytes memory input;
        for (uint256 i = 0; i < g1Points.length; i++) {
            input = bytes.concat(input, abi.encode(g1Points[i], g2Points[i]));
        }

        (bool success, bytes memory output) = address(BLS12_PAIRING_CHECK).staticcall(input);
        require(success, "Pairing failed");
        return abi.decode(output, (bool));
    }

    /// @notice MAP_FP_TO_G1 operation
    /// @param element Fp element
    /// @return result Resulted G1 point
    function MapFpToG1(Fp memory element) internal view returns (G1Point memory result) {
        (bool success, bytes memory output) = address(BLS12_MAP_FP_TO_G1).staticcall(abi.encode(element));
        require(success, "MAP_FP_TO_G1 failed");
        return abi.decode(output, (G1Point));
    }

    /// @notice MAP_FP2_TO_G2 operation
    /// @param element Fp2 element
    /// @return result Resulted G2 point
    function MapFp2ToG2(Fp2 memory element) internal view returns (G2Point memory result) {
        (bool success, bytes memory output) = address(BLS12_MAP_FP2_TO_G2).staticcall(abi.encode(element));
        require(success, "MAP_FP2_TO_G2 failed");
        return abi.decode(output, (G2Point));
    }

    /// @notice Computes a point in G2 from a message
    /// @dev Uses the eip-2537 precompiles
    /// @param message Arbitrarylength byte string to be hashed
    /// @return A point in G2
    function hashToCurveG2(bytes memory message) internal view returns (G2Point memory) {
        // 1. u = hash_to_field(msg, 2)
        Fp2[2] memory u = hashToFieldFp2(message, bytes("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"));
        // 2. Q0 = map_to_curve(u[0])
        G2Point memory q0 = MapFp2ToG2(u[0]);
        // 3. Q1 = map_to_curve(u[1])
        G2Point memory q1 = MapFp2ToG2(u[1]);
        // 4. R = Q0 + Q1
        return G2Add(q0, q1);
    }

    /// @notice Computes a field point from a message
    /// @dev Follows https://datatracker.ietf.org/doc/html/rfc9380#section-5.2
    /// @param message Arbitrarylength byte string to be hashed
    /// @param dst The domain separation tag
    /// @return Two field points
    function hashToFieldFp2(bytes memory message, bytes memory dst) private view returns (Fp2[2] memory) {
        // 1. len_in_bytes = count * m * L
        // so always 2 * 2 * 64 = 256
        uint16 lenInBytes = 256;
        // 2. uniform_bytes = expand_message(msg, DST, len_in_bytes)
        bytes32[] memory pseudoRandomBytes = expandMsgXmd(message, dst, lenInBytes);
        Fp2[2] memory u;
        // No loop here saves 800 gas hardcoding offset an additional 300
        // 3. for i in (0, ..., count - 1):
        // 4.   for j in (0, ..., m - 1):
        // 5.     elm_offset = L * (j + i * m)
        // 6.     tv = substr(uniform_bytes, elm_offset, HTF_L)
        // uint8 HTF_L = 64;
        // bytes memory tv = new bytes(64);
        // 7.     e_j = OS2IP(tv) mod p
        // 8.   u_i = (e_0, ..., e_(m - 1))
        // tv = bytes.concat(pseudo_random_bytes[0], pseudo_random_bytes[1]);
        u[0].c0 = _modfield(pseudoRandomBytes[0], pseudoRandomBytes[1]);
        u[0].c1 = _modfield(pseudoRandomBytes[2], pseudoRandomBytes[3]);
        u[1].c0 = _modfield(pseudoRandomBytes[4], pseudoRandomBytes[5]);
        u[1].c1 = _modfield(pseudoRandomBytes[6], pseudoRandomBytes[7]);
        // 9. return (u_0, ..., u_(count - 1))
        return u;
    }

    /// @notice Computes a field point from a message
    /// @dev Follows https://datatracker.ietf.org/doc/html/rfc9380#section-5.3
    /// @dev bytes32[] because len_in_bytes is always a multiple of 32 in our case even 128
    /// @param message Arbitrarylength byte string to be hashed
    /// @param dst The domain separation tag of at most 255 bytes
    /// @param lenInBytes The length of the requested output in bytes
    /// @return A field point
    function expandMsgXmd(bytes memory message, bytes memory dst, uint16 lenInBytes)
        private
        pure
        returns (bytes32[] memory)
    {
        // 1.  ell = ceil(len_in_bytes / b_in_bytes)
        // b_in_bytes seems to be 32 for sha256
        // ceil the division
        uint256 ell = (lenInBytes - 1) / 32 + 1;

        // 2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
        require(ell <= 255, "len_in_bytes too large for sha256");
        // Not really needed because of parameter type
        // require(lenInBytes <= 65535, "len_in_bytes too large");
        // no length normalizing via hashing
        require(dst.length <= 255, "dst too long");

        bytes memory dstPrime = bytes.concat(dst, bytes1(uint8(dst.length)));

        // 4.  Z_pad = I2OSP(0, s_in_bytes)
        // this should be sha256 blocksize so 64 bytes
        bytes memory zPad = new bytes(64);

        // 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
        // length in byte string?
        bytes2 libStr = bytes2(lenInBytes);

        // 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
        bytes memory msgPrime = bytes.concat(zPad, message, libStr, hex"00", dstPrime);

        // 7.  b_0 = H(msg_prime)
        bytes32 b_0 = sha256(msgPrime);

        bytes32[] memory b = new bytes32[](ell);

        // 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        b[0] = sha256(bytes.concat(b_0, hex"01", dstPrime));

        // 9.  for i in (2, ..., ell):
        for (uint8 i = 2; i <= ell; i++) {
            // 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
            bytes memory tmp = abi.encodePacked(b_0 ^ b[i - 2], i, dstPrime);
            b[i - 1] = sha256(tmp);
        }
        // 11. uniform_bytes = b_1 || ... || b_ell
        // 12. return substr(uniform_bytes, 0, len_in_bytes)
        // Here we don't need the uniform_bytes because b is already properly formed
        return b;
    }

    // passing two bytes32 instead of bytes memory saves approx 700 gas per call
    // Computes the mod against the bls12-381 field modulus
    function _modfield(bytes32 _b1, bytes32 _b2) private view returns (Fp memory r) {
        (bool success, bytes memory output) = address(0x5).staticcall(
            abi.encode(
                // arg[0] = base.length
                0x40,
                // arg[1] = exp.length
                0x20,
                // arg[2] = mod.length
                0x40,
                // arg[3] = base.bits
                // places the first 32 bytes of _b1 and the last 32 bytes of _b2
                _b1,
                _b2,
                // arg[4] = exp
                // exponent always 1
                1,
                // arg[5] = mod
                // this field_modulus as hex 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
                // we add the 0 prefix so that the result will be exactly 64 bytes
                // saves 300 gas per call instead of sending it along every time
                // places the first 32 bytes and the last 32 bytes of the field modulus
                0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7,
                0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
            )
        );
        require(success, "MODEXP failed");
        return abi.decode(output, (Fp));
    }

    // Function to return G1 generator point
    function G1_GENERATOR() internal pure returns (G1Point memory) {
        return G1Point(
            Fp(
                31827880280837800241567138048534752271,
                88385725958748408079899006800036250932223001591707578097800747617502997169851
            ),
            Fp(
                11568204302792691131076548377920244452,
                114417265404584670498511149331300188430316142484413708742216858159411894806497
            )
        );
    }

    // Function to return negated G1 generator point
    function NEGATED_G1_GENERATOR() internal pure returns (G1Point memory) {
        return G1Point(
            Fp(
                31827880280837800241567138048534752271,
                88385725958748408079899006800036250932223001591707578097800747617502997169851
            ),
            Fp(
                22997279242622214937712647648895181298,
                46816884707101390882112958134453447585552332943769894357249934112654335001290
            )
        );
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
    function negate(G1Point memory point) internal pure returns (G1Point memory) {
        uint256[2] memory fieldModulus = baseFieldModulus();
        uint256[2] memory yNeg;

        // Perform word-wise elementary subtraction
        if (fieldModulus[1] < point.y.b) {
            yNeg[1] = type(uint256).max - (point.y.b - fieldModulus[1]) + 1;
            fieldModulus[0] -= 1; // borrow
        } else {
            yNeg[1] = fieldModulus[1] - point.y.b;
        }
        yNeg[0] = fieldModulus[0] - point.y.a;

        return G1Point({ x: point.x, y: Fp(yNeg[0], yNeg[1]) });
    }

    /**
     * @notice Returns true if `a` is lexicographically greater than `b`
     * @dev Adapted from https://github.com/NethermindEth/Taiko-Preconf-AVS/blob/004d407105578a83c4815e7ec2c55ec467b9ed3f/SmartContracts/src/libraries/BLS12381.sol#L124
     * @dev It makes the comparison bit-wise.
     * This functions also assumes that the passed values are 48-byte long BLS pub keys that have
     * 16 functional bytes in the first word, and 32 bytes in the second.
     */
    // function _greaterThan(uint256[2] memory a, uint256[2] memory b) internal pure returns (bool) {
    function _greaterThan(Fp memory a, Fp memory b) internal pure returns (bool) {
        uint256 wordA;
        uint256 wordB;
        uint256 mask;

        // Only compare the unequal words
        if (a.a == b.a) {
            wordA = a.b;
            wordB = b.b;
            mask = 1 << 255;
        } else {
            wordA = a.a;
            wordB = b.a;
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
    function toPublicKey(uint256 privateKey) internal view returns (G1Point memory) {
        return G1Mul(G1_GENERATOR(), privateKey);
    }

    /// @notice Converts a message to a G2 point
    /// @param message Arbitrarylength byte string to be hashed with the domainSeparator
    /// @param domainSeparator The domain separation tag
    /// @return A point in G2
    function toMessagePoint(bytes memory message, bytes memory domainSeparator)
        internal
        view
        returns (G2Point memory)
    {
        return MapFp2ToG2(Fp2(Fp(0, 0), Fp(0, uint256(keccak256(abi.encodePacked(domainSeparator, message))))));
    }

    /// @notice Signs a message
    /// @param message Arbitrarylength byte string to be hashed with the domainSeparator
    /// @param privateKey The private key to sign with
    /// @param domainSeparator The domain separation tag
    /// @return A signature in G2
    function sign(bytes memory message, uint256 privateKey, bytes memory domainSeparator)
        internal
        view
        returns (G2Point memory)
    {
        return G2Mul(toMessagePoint(message, domainSeparator), privateKey);
    }

    /// @notice Verifies a signature
    /// @param message Arbitrarylength byte string to be hashed
    /// @param signature The signature to verify
    /// @param publicKey The public key to verify against
    /// @param domainSeparator The domain separation tag
    /// @return True if the signature is valid, false otherwise
    function verify(
        bytes memory message,
        G2Point memory signature,
        G1Point memory publicKey,
        bytes memory domainSeparator
    ) public view returns (bool) {
        // Hash the message bytes into a G2 point
        BLS.G2Point memory messagePoint = toMessagePoint(message, domainSeparator);

        // Invoke the pairing check to verify the signature.
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = NEGATED_G1_GENERATOR();
        g1Points[1] = publicKey;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = signature;
        g2Points[1] = messagePoint;

        return BLS.Pairing(g1Points, g2Points);
    }

    /**
     * @notice Returns a G1Point in the compressed form
     * @dev Adapted from https://github.com/NethermindEth/Taiko-Preconf-AVS/blob/004d407105578a83c4815e7ec2c55ec467b9ed3f/SmartContracts/src/libraries/BLS12381.sol#L124
     * @dev Originally based on https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization
     * @param point The G1 point to compress
     */
    function compress(G1Point memory point) internal pure returns (Fp memory) {
        Fp memory r = point.x;

        // Set the first MSB
        r.a = r.a | (1 << 127);

        // Second MSB is left to be 0 since we are assuming that no infinity points are involved

        // Set the third MSB if point.y is lexicographically larger than the y in negated point
        if (_greaterThan(point.y, negate(point).y)) {
            r.a = r.a | (1 << 125);
        }

        return r;
    }
}
