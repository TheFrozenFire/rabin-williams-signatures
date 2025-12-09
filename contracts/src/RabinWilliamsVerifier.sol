// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * @title RabinWilliamsVerifier
 * @notice Verifies Rabin-Williams digital signatures
 * @dev This contract verifies signatures using the Rabin-Williams scheme
 *      with SHA-256 as the hash function. The signature format is:
 *      - First byte: flags (bit 0 = e, bit 1 = f)
 *      - Remaining bytes: signature value x (big-endian)
 */
contract RabinWilliamsVerifier {
    /**
     * @notice Verifies a Rabin-Williams signature
     * @param n The public key modulus (1024-bit, hex-encoded)
     * @param message The message that was signed
     * @param signature The signature to verify (hex-encoded)
     * @return isValid True if the signature is valid, false otherwise
     */
    function verify(
        bytes memory n,
        bytes memory message,
        bytes memory signature
    ) public view returns (bool isValid) {
        // Hash the message using SHA-256
        bytes32 messageHash = sha256(message);
        
        // Extract signature components
        (int256 e, uint256 f, bytes memory x) = extractSignature(signature);
        
        // Validate signature format
        if (x.length == 0 || x.length > 128) {
            return false;
        }
        
        // Compute x² mod n
        bytes memory xSquared = modExp(x, 2, n);
        
        // Apply transformation based on e and f
        bytes memory result;
        if (e == 1 && f == 1) {
            result = xSquared;
        } else if (e == 1 && f == 2) {
            bytes memory nPlusOne = addOne(n);
            bytes memory twoInv = divByTwo(nPlusOne);
            result = modMul(xSquared, twoInv, n);
        } else if (e == -1 && f == 1) {
            result = modSub(n, xSquared, n);
        } else if (e == -1 && f == 2) {
            bytes memory negXSquared = modSub(n, xSquared, n);
            bytes memory nPlusOne = addOne(n);
            bytes memory twoInv = divByTwo(nPlusOne);
            result = modMul(negXSquared, twoInv, n);
        } else {
            return false;
        }
        
        // Compare result with message hash
        // The result is a BigUint modulo n, and we need to compare it with the hash (32 bytes)
        // Remove leading zeros first
        bytes memory cleanResult = removeLeadingZeros(result);
        bytes memory hashBytes = abi.encodePacked(messageHash);
        
        // The hash is always 32 bytes. The result should match it exactly.
        // If result is longer than 32 bytes, it can't equal a 32-byte hash
        if (cleanResult.length > 32) {
            return false;
        }
        
        // If result is shorter than 32 bytes, pad with leading zeros
        if (cleanResult.length < 32) {
            bytes memory padded = new bytes(32);
            uint256 padStart = 32 - cleanResult.length;
            for (uint256 i = 0; i < cleanResult.length; i++) {
                padded[padStart + i] = cleanResult[i];
            }
            return bytesEqual(padded, hashBytes);
        }
        
        // Result is exactly 32 bytes, compare directly
        return bytesEqual(cleanResult, hashBytes);
    }
    
    /**
     * @notice Extracts e, f, and x from a signature
     * @param signature The signature bytes
     * @return e The e value (1 or -1)
     * @return f The f value (1 or 2)
     * @return x The signature value
     */
    function extractSignature(bytes memory signature)
        internal
        pure
        returns (int256 e, uint256 f, bytes memory x)
    {
        if (signature.length < 2) {
            revert("Invalid signature length");
        }
        
        uint8 firstByte = uint8(signature[0]);
        
        // Validate that only bits 0 and 1 are used
        if (firstByte & 0xFC != 0) {
            revert("Invalid signature flags");
        }
        
        // Extract e and f from first byte
        e = (firstByte & 1) == 0 ? int256(1) : int256(-1);
        f = (firstByte & 2) == 0 ? 1 : 2;
        
        // Extract x (remaining bytes)
        x = new bytes(signature.length - 1);
        for (uint256 i = 1; i < signature.length; i++) {
            x[i - 1] = signature[i];
        }
    }
    
    /**
     * @notice Computes base^exponent mod modulus for big integers
     * @dev Uses the modExp precompile (address 0x05)
     */
    function modExp(
        bytes memory base,
        uint256 exponent,
        bytes memory modulus
    ) internal view returns (bytes memory) {
        uint256 baseLen = base.length;
        uint256 modLen = modulus.length;
        uint256 expLen = 32; // exponent is a uint256, so 32 bytes
        
        // The modExp precompile (EIP-198) expects:
        // baseLen (32 bytes, big-endian) || expLen (32 bytes, big-endian) || modLen (32 bytes, big-endian) || 
        // base (baseLen bytes) || exponent (expLen bytes, big-endian) || modulus (modLen bytes)
        
        // Use abi.encode to get 32-byte length fields, then concatenate
        bytes memory lenPart = abi.encode(baseLen, expLen, modLen);
        bytes memory expBytes = abi.encode(exponent);
        
        // Concatenate: lengths (96 bytes) + base + exponent (32 bytes) + modulus
        bytes memory input = abi.encodePacked(lenPart, base, expBytes, modulus);
        
        // Call the modExp precompile (address 0x05)
        (bool success, bytes memory result) = address(0x05).staticcall(input);
        require(success, "modExp precompile failed");
        
        // Remove leading zeros from result
        return removeLeadingZeros(result);
    }
    
    /**
     * @notice Adds 1 to a big integer
     */
    function addOne(bytes memory a) internal pure returns (bytes memory) {
        bytes memory result = new bytes(a.length);
        uint256 carry = 1;
        
        for (uint256 i = a.length; i > 0; i--) {
            uint256 idx = i - 1;
            uint256 sum = uint8(a[idx]) + carry;
            result[idx] = bytes1(uint8(sum & 0xFF));
            carry = sum >> 8;
        }
        
        if (carry > 0) {
            // Need to extend result
            bytes memory extended = new bytes(result.length + 1);
            extended[0] = bytes1(uint8(carry));
            for (uint256 i = 0; i < result.length; i++) {
                extended[i + 1] = result[i];
            }
            return extended;
        }
        
        return removeLeadingZeros(result);
    }
    
    /**
     * @notice Divides a big integer by 2
     */
    function divByTwo(bytes memory a) internal pure returns (bytes memory) {
        bytes memory result = new bytes(a.length);
        uint256 carry = 0;
        
        for (uint256 i = 0; i < a.length; i++) {
            uint256 value = (uint256(uint8(a[i])) + (carry << 8));
            result[i] = bytes1(uint8(value >> 1));
            carry = value & 1;
        }
        
        return removeLeadingZeros(result);
    }
    
    /**
     * @notice Modular multiplication: (a * b) mod n
     * @dev Uses modExp precompile with exponent 1 for efficient modular multiplication
     */
    function modMul(
        bytes memory a,
        bytes memory b,
        bytes memory n
    ) internal view returns (bytes memory) {
        // Compute a * b first
        bytes memory product = mul(a, b);
        
        // Use modExp with exponent 1 to compute product^1 mod n = product mod n
        // This is more efficient than repeated subtraction
        return modExp(product, 1, n);
    }
    
    /**
     * @notice Modular subtraction: (n - a) mod n
     * @dev Since a is already reduced mod n (a < n), n - a is the result
     *      No further reduction needed as n - a < n when a > 0
     */
    function modSub(
        bytes memory n,
        bytes memory a,
        bytes memory modulus
    ) internal pure returns (bytes memory) {
        // For (n - a) mod n where a < n:
        // n - a is positive and < n (when a > 0), so no reduction needed
        // Just compute n - a directly
        return sub(n, a);
    }
    
    /**
     * @notice Multiplies two big integers (big-endian)
     * @dev Standard schoolbook multiplication algorithm
     */
    function mul(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        uint256 aLen = a.length;
        uint256 bLen = b.length;
        bytes memory result = new bytes(aLen + bLen);
        
        // Multiply from least significant byte to most significant
        for (uint256 i = 0; i < aLen; i++) {
            uint256 carry = 0;
            for (uint256 j = 0; j < bLen; j++) {
                // Work from right to left (least significant to most)
                uint256 aIdx = aLen - 1 - i;
                uint256 bIdx = bLen - 1 - j;
                uint256 resultIdx = (aLen + bLen) - 1 - (i + j);
                
                uint256 product = uint256(uint8(a[aIdx])) * uint256(uint8(b[bIdx])) + 
                                 uint256(uint8(result[resultIdx])) + carry;
                result[resultIdx] = bytes1(uint8(product & 0xFF));
                carry = product >> 8;
            }
            
            // Handle remaining carry
            if (carry > 0 && i + bLen < aLen + bLen) {
                uint256 carryIdx = (aLen + bLen) - 1 - (i + bLen);
                uint256 sum = uint256(uint8(result[carryIdx])) + carry;
                result[carryIdx] = bytes1(uint8(sum & 0xFF));
                if (sum >> 8 > 0 && carryIdx > 0) {
                    result[carryIdx - 1] = bytes1(uint8(sum >> 8));
                }
            }
        }
        
        return removeLeadingZeros(result);
    }
    
    /**
     * @notice Subtracts b from a (assumes a >= b)
     */
    function sub(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        bytes memory result = new bytes(a.length);
        uint256 borrow = 0;
        
        for (uint256 i = 0; i < a.length; i++) {
            uint256 idx = a.length - 1 - i;
            uint256 aVal = uint256(uint8(a[idx]));
            uint256 bVal = i < b.length ? uint256(uint8(b[b.length - 1 - i])) : 0;
            
            uint256 diff;
            if (aVal >= bVal + borrow) {
                diff = aVal - bVal - borrow;
                borrow = 0;
            } else {
                diff = 256 + aVal - bVal - borrow;
                borrow = 1;
            }
            
            result[idx] = bytes1(uint8(diff));
        }
        
        return removeLeadingZeros(result);
    }
    
    /**
     * @notice Adds two big integers
     */
    function add(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        uint256 maxLen = a.length > b.length ? a.length : b.length;
        bytes memory result = new bytes(maxLen + 1);
        uint256 carry = 0;
        
        for (uint256 i = 0; i < maxLen; i++) {
            uint256 aVal = i < a.length ? uint256(uint8(a[a.length - 1 - i])) : 0;
            uint256 bVal = i < b.length ? uint256(uint8(b[b.length - 1 - i])) : 0;
            
            uint256 sum = aVal + bVal + carry;
            result[maxLen - i] = bytes1(uint8(sum & 0xFF));
            carry = sum >> 8;
        }
        
        if (carry > 0) {
            result[0] = bytes1(uint8(carry));
        }
        
        return removeLeadingZeros(result);
    }
    
    /**
     * @notice Computes a mod n using efficient reduction
     * @dev Uses repeated subtraction but with optimization for large numbers
     */
    function mod(bytes memory a, bytes memory n) internal pure returns (bytes memory) {
        bytes memory result = removeLeadingZeros(a);
        bytes memory modulus = removeLeadingZeros(n);
        
        // If a < n, return a
        if (compare(result, modulus) < 0) {
            return result;
        }
        
        // For efficiency, subtract multiples of n when possible
        // But for simplicity and correctness, we'll do repeated subtraction
        // with a limit to prevent infinite loops
        uint256 iterations = 0;
        uint256 maxIterations = 1000; // Safety limit
        
        while (compare(result, modulus) >= 0 && iterations < maxIterations) {
            result = sub(result, modulus);
            result = removeLeadingZeros(result);
            iterations++;
        }
        
        // If we hit the limit, the number is too large - this shouldn't happen
        // in normal operation since modExp should return reduced results
        if (iterations >= maxIterations) {
            revert("Mod reduction failed - number too large");
        }
        
        return result;
    }
    
    /**
     * @notice Compares two big integers
     * @return -1 if a < b, 0 if a == b, 1 if a > b
     */
    function compare(bytes memory a, bytes memory b) internal pure returns (int256) {
        bytes memory aClean = removeLeadingZeros(a);
        bytes memory bClean = removeLeadingZeros(b);
        
        if (aClean.length < bClean.length) return -1;
        if (aClean.length > bClean.length) return 1;
        
        for (uint256 i = 0; i < aClean.length; i++) {
            if (uint8(aClean[i]) < uint8(bClean[i])) return -1;
            if (uint8(aClean[i]) > uint8(bClean[i])) return 1;
        }
        
        return 0;
    }
    
    /**
     * @notice Removes leading zeros from a byte array
     */
    function removeLeadingZeros(bytes memory data) internal pure returns (bytes memory) {
        uint256 start = 0;
        while (start < data.length && data[start] == 0) {
            start++;
        }
        
        if (start == data.length) {
            return new bytes(1); // Return single zero byte
        }
        
        bytes memory result = new bytes(data.length - start);
        for (uint256 i = 0; i < result.length; i++) {
            result[i] = data[start + i];
        }
        
        return result;
    }
    
    /**
     * @notice Compares two byte arrays for equality
     */
    function bytesEqual(bytes memory a, bytes memory b) internal pure returns (bool) {
        if (a.length != b.length) return false;
        for (uint256 i = 0; i < a.length; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}

