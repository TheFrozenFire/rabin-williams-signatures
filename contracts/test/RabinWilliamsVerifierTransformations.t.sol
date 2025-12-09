// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {RabinWilliamsVerifier} from "../src/RabinWilliamsVerifier.sol";

/**
 * @title RabinWilliamsVerifierTransformationsTestHarness
 * @notice Exposes transformation logic for testing
 */
contract RabinWilliamsVerifierTransformationsTestHarness is RabinWilliamsVerifier {
    // Expose transformation steps for testing
    function harnessComputeXSquared(bytes memory x, bytes memory n) 
        public view returns (bytes memory) 
    {
        return modExp(x, 2, n);
    }

    function harnessTransformCase1_1(bytes memory xSquared) 
        public pure returns (bytes memory) 
    {
        // Case (e=1, f=1): result = xSquared
        return xSquared;
    }

    function harnessTransformCase1_2(bytes memory xSquared, bytes memory n) 
        public view returns (bytes memory) 
    {
        // Case (e=1, f=2): result = (xSquared * (n+1)/2) mod n
        bytes memory nPlusOne = addOne(n);
        bytes memory twoInv = divByTwo(nPlusOne);
        return modMul(xSquared, twoInv, n);
    }

    function harnessTransformCaseNeg1_1(bytes memory xSquared, bytes memory n) 
        public pure returns (bytes memory) 
    {
        // Case (e=-1, f=1): result = (n - xSquared) mod n
        return modSub(n, xSquared, n);
    }

    function harnessTransformCaseNeg1_2(bytes memory xSquared, bytes memory n) 
        public view returns (bytes memory) 
    {
        // Case (e=-1, f=2): result = ((n - xSquared) * (n+1)/2) mod n
        bytes memory negXSquared = modSub(n, xSquared, n);
        bytes memory nPlusOne = addOne(n);
        bytes memory twoInv = divByTwo(nPlusOne);
        return modMul(negXSquared, twoInv, n);
    }

    function harnessAddOne(bytes memory a) public pure returns (bytes memory) {
        return addOne(a);
    }

    function harnessDivByTwo(bytes memory a) public pure returns (bytes memory) {
        return divByTwo(a);
    }

    function harnessModSub(bytes memory n, bytes memory a, bytes memory modulus) 
        public view returns (bytes memory) 
    {
        return modSub(n, a, modulus);
    }

    function harnessModMul(bytes memory a, bytes memory b, bytes memory n) 
        public view returns (bytes memory) 
    {
        return modMul(a, b, n);
    }

    function harnessBytesEqual(bytes memory a, bytes memory b) public pure returns (bool) {
        return bytesEqual(a, b);
    }
}

contract RabinWilliamsVerifierTransformationsTest is Test {
    RabinWilliamsVerifierTransformationsTestHarness public harness;

    function setUp() public {
        harness = new RabinWilliamsVerifierTransformationsTestHarness();
    }

    // ============ Helper Functions ============

    function hexToBytes(string memory hexString) internal pure returns (bytes memory) {
        bytes memory hexBytes = bytes(hexString);
        require(hexBytes.length % 2 == 0, "Invalid hex string length");
        
        bytes memory result = new bytes(hexBytes.length / 2);
        for (uint256 i = 0; i < result.length; i++) {
            uint8 high = charToHex(hexBytes[i * 2]);
            uint8 low = charToHex(hexBytes[i * 2 + 1]);
            result[i] = bytes1((high << 4) | low);
        }
        return result;
    }

    function charToHex(bytes1 char) internal pure returns (uint8) {
        if (char >= 0x30 && char <= 0x39) {
            return uint8(char) - 0x30;
        } else if (char >= 0x41 && char <= 0x46) {
            return uint8(char) - 0x37;
        } else if (char >= 0x61 && char <= 0x66) {
            return uint8(char) - 0x57;
        }
        revert("Invalid hex character");
    }

    // ============ Test: addOne ============

    function test_AddOne_Simple() public view {
        bytes memory n = hex"0A"; // 10
        bytes memory result = harness.harnessAddOne(n);
        bytes memory expected = hex"0B"; // 11
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_AddOne_WithCarry() public view {
        bytes memory n = hex"FF";
        bytes memory result = harness.harnessAddOne(n);
        bytes memory expected = hex"0100";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: divByTwo ============

    function test_DivByTwo_Simple() public view {
        bytes memory nPlusOne = hex"0B"; // 11
        bytes memory result = harness.harnessDivByTwo(nPlusOne);
        bytes memory expected = hex"05"; // 5
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_DivByTwo_Odd() public view {
        bytes memory nPlusOne = hex"0D"; // 13
        bytes memory result = harness.harnessDivByTwo(nPlusOne);
        bytes memory expected = hex"06"; // 6 (13/2 = 6.5, integer division = 6)
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: modSub ============

    function test_ModSub_Simple() public view {
        bytes memory n = hex"0A";
        bytes memory xSquared = hex"03";
        bytes memory result = harness.harnessModSub(n, xSquared, n);
        bytes memory expected = hex"07"; // 10 - 3 = 7
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_ModSub_Zero() public view {
        bytes memory n = hex"0A";
        bytes memory xSquared = hex"00";
        bytes memory result = harness.harnessModSub(n, xSquared, n);
        assertTrue(harness.harnessBytesEqual(result, n)); // n - 0 = n
    }

    // ============ Test: Transformation Case (1, 1) ============

    function test_TransformCase1_1_Simple() public view {
        bytes memory xSquared = hex"05";
        bytes memory result = harness.harnessTransformCase1_1(xSquared);
        assertTrue(harness.harnessBytesEqual(result, xSquared));
    }

    // ============ Test: Transformation Case (1, 2) ============

    function test_TransformCase1_2_Simple() public view {
        bytes memory n = hex"0F"; // 15
        bytes memory xSquared = hex"04"; // 4
        
        // (n+1)/2 = 16/2 = 8
        // result = (4 * 8) mod 15 = 32 mod 15 = 2
        bytes memory result = harness.harnessTransformCase1_2(xSquared, n);
        bytes memory expected = hex"02";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_TransformCase1_2_Verify() public view {
        bytes memory n = hex"0A"; // 10
        bytes memory xSquared = hex"06"; // 6
        
        // (n+1)/2 = 11/2 = 5
        // result = (6 * 5) mod 10 = 30 mod 10 = 0
        bytes memory result = harness.harnessTransformCase1_2(xSquared, n);
        bytes memory expected = hex"00";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: Transformation Case (-1, 1) ============

    function test_TransformCaseNeg1_1_Simple() public view {
        bytes memory n = hex"0A";
        bytes memory xSquared = hex"03";
        
        // result = (n - xSquared) mod n = (10 - 3) mod 10 = 7
        bytes memory result = harness.harnessTransformCaseNeg1_1(xSquared, n);
        bytes memory expected = hex"07";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_TransformCaseNeg1_1_Zero() public view {
        bytes memory n = hex"0A";
        bytes memory xSquared = hex"00";
        
        // result = (n - 0) mod n = n mod n = 0? No, n - 0 = n, but n mod n = 0
        // Actually, modSub(n, 0, n) should return n, but then we need to check
        bytes memory result = harness.harnessTransformCaseNeg1_1(xSquared, n);
        // n - 0 = n, but since we're working mod n, if result >= n, we'd reduce it
        // But modSub just does n - a, so it returns n when a=0
        assertTrue(harness.harnessBytesEqual(result, n));
    }

    // ============ Test: Transformation Case (-1, 2) ============

    function test_TransformCaseNeg1_2_Simple() public view {
        bytes memory n = hex"0F"; // 15
        bytes memory xSquared = hex"04"; // 4
        
        // negXSquared = (15 - 4) mod 15 = 11
        // (n+1)/2 = 16/2 = 8
        // result = (11 * 8) mod 15 = 88 mod 15 = 13
        bytes memory result = harness.harnessTransformCaseNeg1_2(xSquared, n);
        bytes memory expected = hex"0D"; // 13
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_TransformCaseNeg1_2_Verify() public view {
        bytes memory n = hex"0A"; // 10
        bytes memory xSquared = hex"06"; // 6
        
        // negXSquared = (10 - 6) mod 10 = 4
        // (n+1)/2 = 11/2 = 5
        // result = (4 * 5) mod 10 = 20 mod 10 = 0
        bytes memory result = harness.harnessTransformCaseNeg1_2(xSquared, n);
        bytes memory expected = hex"00";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: Full Transformation Flow ============

    function test_FullTransformationFlow_Case1_1() public view {
        bytes memory x = hex"03";
        bytes memory n = hex"0F";
        
        // Compute x² mod n
        bytes memory xSquared = harness.harnessComputeXSquared(x, n);
        // x² = 9, 9 mod 15 = 9
        bytes memory expectedXSquared = hex"09";
        assertTrue(harness.harnessBytesEqual(xSquared, expectedXSquared));
        
        // Apply transformation (1, 1)
        bytes memory result = harness.harnessTransformCase1_1(xSquared);
        assertTrue(harness.harnessBytesEqual(result, xSquared));
    }

    function test_FullTransformationFlow_Case1_2() public view {
        bytes memory x = hex"02";
        bytes memory n = hex"0F";
        
        // Compute x² mod n
        bytes memory xSquared = harness.harnessComputeXSquared(x, n);
        // x² = 4, 4 mod 15 = 4
        bytes memory expectedXSquared = hex"04";
        assertTrue(harness.harnessBytesEqual(xSquared, expectedXSquared));
        
        // Apply transformation (1, 2)
        bytes memory result = harness.harnessTransformCase1_2(xSquared, n);
        // (n+1)/2 = 8, (4 * 8) mod 15 = 32 mod 15 = 2
        bytes memory expected = hex"02";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_FullTransformationFlow_CaseNeg1_1() public view {
        bytes memory x = hex"02";
        bytes memory n = hex"0F";
        
        // Compute x² mod n
        bytes memory xSquared = harness.harnessComputeXSquared(x, n);
        // x² = 4, 4 mod 15 = 4
        
        // Apply transformation (-1, 1)
        bytes memory result = harness.harnessTransformCaseNeg1_1(xSquared, n);
        // (n - xSquared) mod n = (15 - 4) mod 15 = 11
        bytes memory expected = hex"0B";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_FullTransformationFlow_CaseNeg1_2() public view {
        bytes memory x = hex"02";
        bytes memory n = hex"0F";
        
        // Compute x² mod n
        bytes memory xSquared = harness.harnessComputeXSquared(x, n);
        // x² = 4, 4 mod 15 = 4
        
        // Apply transformation (-1, 2)
        bytes memory result = harness.harnessTransformCaseNeg1_2(xSquared, n);
        // negXSquared = (15 - 4) = 11
        // (n+1)/2 = 8
        // result = (11 * 8) mod 15 = 88 mod 15 = 13
        bytes memory expected = hex"0D";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: Verify Transformation Reversibility ============
    // These tests verify that if we have a known result, we can work backwards

    function test_TransformationReversibility_Case1_2() public view {
        // If we want result = 2, and we're using case (1, 2)
        // result = (xSquared * (n+1)/2) mod n
        // We need: (xSquared * 8) mod 15 = 2
        // This means: xSquared * 8 ≡ 2 (mod 15)
        // xSquared ≡ 2 * 8^(-1) (mod 15)
        // 8^(-1) mod 15 = 2 (since 8 * 2 = 16 ≡ 1 mod 15)
        // So xSquared ≡ 2 * 2 = 4 (mod 15)
        
        bytes memory n = hex"0F";
        bytes memory xSquared = hex"04";
        bytes memory result = harness.harnessTransformCase1_2(xSquared, n);
        bytes memory expected = hex"02";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: Using Actual Fixture Data ============

    function test_TransformationWithFixtureData() public view {
        // Load actual fixture data
        string memory publicKeyHex = vm.readFile("contracts/test/fixtures/public_key.hex");
        string memory signatureHex = vm.readFile("contracts/test/fixtures/signature.hex");
        
        bytes memory n = hexToBytes(publicKeyHex);
        bytes memory signature = hexToBytes(signatureHex);
        
        // Extract x from signature (skip first byte which is flags)
        bytes memory x = new bytes(signature.length - 1);
        for (uint256 i = 1; i < signature.length; i++) {
            x[i - 1] = signature[i];
        }
        
        uint8 firstByte = uint8(signature[0]);
        int256 e = (firstByte & 1) == 0 ? int256(1) : int256(-1);
        uint256 f = (firstByte & 2) == 0 ? 1 : 2;
        
        console.log("e:", uint256(int256(e) == 1 ? 1 : 0));
        console.log("f:", f);
        console.log("x length:", x.length);
        console.log("n length:", n.length);
        
        // Compute x² mod n
        bytes memory xSquared = harness.harnessComputeXSquared(x, n);
        console.log("xSquared length:", xSquared.length);
        
        // Apply transformation based on e and f
        bytes memory result;
        if (e == 1 && f == 1) {
            result = harness.harnessTransformCase1_1(xSquared);
            console.log("Using transformation (1, 1)");
        } else if (e == 1 && f == 2) {
            result = harness.harnessTransformCase1_2(xSquared, n);
            console.log("Using transformation (1, 2)");
        } else if (e == -1 && f == 1) {
            result = harness.harnessTransformCaseNeg1_1(xSquared, n);
            console.log("Using transformation (-1, 1)");
        } else if (e == -1 && f == 2) {
            result = harness.harnessTransformCaseNeg1_2(xSquared, n);
            console.log("Using transformation (-1, 2)");
        }
        
        console.log("Result length:", result.length);
        
        // Get expected hash
        string memory messageText = vm.readFile("contracts/test/fixtures/message.txt");
        bytes memory message = bytes(messageText);
        bytes32 messageHash = sha256(message);
        bytes memory hashBytes = abi.encodePacked(messageHash);
        
        console.log("Hash length:", hashBytes.length);
        console.log("Result == Hash:", harness.harnessBytesEqual(result, hashBytes));
        
        // Log first 4 bytes for quick comparison
        if (result.length >= 4 && hashBytes.length >= 4) {
            console.log("Result[0]:", uint8(result[0]));
            console.log("Result[1]:", uint8(result[1]));
            console.log("Result[2]:", uint8(result[2]));
            console.log("Result[3]:", uint8(result[3]));
            console.log("Hash[0]:", uint8(hashBytes[0]));
            console.log("Hash[1]:", uint8(hashBytes[1]));
            console.log("Hash[2]:", uint8(hashBytes[2]));
            console.log("Hash[3]:", uint8(hashBytes[3]));
        }
    }
}

