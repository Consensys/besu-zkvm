/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
package org.hyperledger.besu.riscv.poc;

import org.hyperledger.besu.nativelib.gnark.LibGnarkEIP2537Graal;
import org.hyperledger.besu.nativelib.gnark.LibGnarkUtils;

import java.nio.charset.StandardCharsets;

/**
 * Test case for Gnark BLS12-381 G2 point validation operations.
 * Tests if a valid G2 point is correctly identified as being on the curve.
 * This exercises Gnark's native cryptographic operations in a GraalVM native-image context.
 */
public class GnarkG2PointTest {

    /** Private constructor to prevent instantiation. */
    private GnarkG2PointTest() {}

    // Valid G2 point - 256 bytes (512 hex chars)
    private static final String VALID_G2_POINT =
        "00000000000000000000000000000000124aca13d9ead2e5194eb097360743fc996551a5f339d644ded3571c5588a1fedf3f26ecdca73845241e47337e8ad990" +
        "000000000000000000000000000000000299bfd77515b688335e58acb31f7e0e6416840989cb08775287f90f7e6c921438b7b476cfa387742fcdc43bcecfe45f" +
        "00000000000000000000000000000000032e78350f525d673e75a3430048a7931d21264ac1b2c8dc58aee07e77790dfc9afb530b004145f0040c48bce128135e" +
        "0000000000000000000000000000000015963bcbd8fa50808bdce4f8de40eb9706c1a41ada22f0e469ecceb3e0b0fa3404ccdcc66a286b5a9e221c4a088a9145";

    /**
     * Runs the Gnark G2 point validation test.
     */
    public static void runTest() {
        System.out.println("TEST: G2 IsOnCurve - Valid Point");
        System.out.println("-----------------------------------");

        final byte[] input = hexStringToBytes(VALID_G2_POINT);
        final byte[] error = new byte[LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];

        System.out.println("Input (hex): " + VALID_G2_POINT);
        System.out.println("Input length: " + input.length + " bytes");

        boolean result = LibGnarkEIP2537Graal.eip2537G2IsOnCurve(
            input, error, input.length, LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);

        System.out.println("Result: " + result);
        System.out.println("Expected: true");
        System.out.println("Status: " + (result ? "PASS" : "FAIL"));

        // Print error message if any
        int errorLen = LibGnarkUtils.findFirstTrailingZeroIndex(error);
        if (errorLen > 0) {
            String errorMsg = new String(error, 0, errorLen, StandardCharsets.UTF_8);
            System.out.println("Error message: " + errorMsg);
        } else {
            System.out.println("Error message: <none>");
        }

        System.out.println();
        System.out.println("Test completed successfully!");
    }

    /**
     * Convert hex string to byte array.
     *
     * @param hex hexadecimal string (must have even length)
     * @return byte array representation of the hex string
     */
    private static byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
}
