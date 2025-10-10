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

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

/**
 * Test case for BouncyCastle secp256r1 (P-256) elliptic curve operations.
 * Generates a random key pair, signs a message hash, and displays the signature components.
 * This exercises BouncyCastle's cryptographic operations in a GraalVM native-image context.
 */
public class BouncyCastleR1Test {

    /** Private constructor to prevent instantiation. */
    private BouncyCastleR1Test() {}

    /**
     * Runs the BouncyCastle secp256r1 test.
     *
     * @throws Exception if cryptographic operations fail
     */
    public static void runTest() throws Exception {
        // Add BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());

        SecureRandom random = new SecureRandom();

        // Generate random 32-byte message hash
        byte[] messageHash = new byte[32];
        random.nextBytes(messageHash);

        System.out.println("Message hash: " + Bytes.of(messageHash).toHexString());

        // Generate P-256 key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecSpec, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        // Extract public key coordinates
        var pubKeyPoint = publicKey.getW();
        BigInteger x = pubKeyPoint.getAffineX();
        BigInteger y = pubKeyPoint.getAffineY();

        System.out.println("Public key X: " + safeBigIntTo32bytes(x));
        System.out.println("Public key Y: " + safeBigIntTo32bytes(y));

        // Sign the message hash
        Signature signer = Signature.getInstance("NONEwithECDSA", "BC");
        signer.initSign(privateKey, random);
        signer.update(messageHash);
        byte[] signature = signer.sign();

        System.out.println("DER Signature: " + Bytes.of(signature).toHexString());

        // Parse DER signature to extract r and s
        BigInteger[] rs = parseDERSignature(signature);
        BigInteger r = rs[0];
        BigInteger s = rs[1];

        System.out.println("Signature R: " + safeBigIntTo32bytes(r));
        System.out.println("Signature S: " + safeBigIntTo32bytes(s));

        // Verify the signature
        Signature verifier = Signature.getInstance("NONEwithECDSA", "BC");
        verifier.initVerify(publicKey);
        verifier.update(messageHash);
        boolean isValid = verifier.verify(signature);

        System.out.println("Signature valid: " + isValid);
        System.out.println();
        System.out.println("Test completed successfully!");
    }

    /**
     * Converts a BigInteger to a 32-byte hex string, handling padding and trimming.
     *
     * @param bigint the BigInteger to convert
     * @return hex string representation (unprefixed, 32 bytes)
     */
    private static String safeBigIntTo32bytes(final BigInteger bigint) {
        var bytesVal = Bytes.of(bigint.toByteArray());
        return bytesVal.size() > 32 ?
            bytesVal.slice(1, 32).toUnprefixedHexString() :
            bytesVal.toUnprefixedHexString();
    }

    /**
     * Parses a DER-encoded ECDSA signature to extract r and s values.
     *
     * @param derSignature DER-encoded signature bytes
     * @return array containing [r, s] as BigIntegers
     * @throws IllegalArgumentException if signature format is invalid
     */
    private static BigInteger[] parseDERSignature(final byte[] derSignature) {
        int offset = 0;

        // Skip SEQUENCE tag and length
        if (derSignature[offset] != 0x30) {
            throw new IllegalArgumentException("Invalid DER signature format");
        }
        offset += 2; // Skip tag and length

        // Parse r
        if (derSignature[offset] != 0x02) {
            throw new IllegalArgumentException("Invalid DER signature format - r not INTEGER");
        }
        offset++;
        int rLength = derSignature[offset++] & 0xFF;
        byte[] rBytes = new byte[rLength];
        System.arraycopy(derSignature, offset, rBytes, 0, rLength);
        BigInteger r = new BigInteger(1, rBytes);
        offset += rLength;

        // Parse s
        if (derSignature[offset] != 0x02) {
            throw new IllegalArgumentException("Invalid DER signature format - s not INTEGER");
        }
        offset++;
        int sLength = derSignature[offset++] & 0xFF;
        byte[] sBytes = new byte[sLength];
        System.arraycopy(derSignature, offset, sBytes, 0, sLength);
        BigInteger s = new BigInteger(1, sBytes);

        return new BigInteger[]{r, s};
    }
}
