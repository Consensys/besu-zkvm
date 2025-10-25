/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.riscv.poc.crypto;

import org.hyperledger.besu.crypto.AbstractSECP256;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1Graal;

import java.math.BigInteger;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * GraalVM-compatible SECP256K1 implementation using LibSecp256k1Graal.
 *
 * <p>This implementation uses the GraalVM-compatible native secp256k1 library which is compatible
 * with native image compilation, unlike the JNA-based LibSecp256k1.
 */
public class SECP256K1Graal extends AbstractSECP256 {

  private static final Logger LOG = LoggerFactory.getLogger(SECP256K1Graal.class);

  /** The constant CURVE_NAME. */
  public static final String CURVE_NAME = "secp256k1";

  private boolean useNative;

  /** Instantiates a new SECP256K1Graal. */
  public SECP256K1Graal() {
    super(CURVE_NAME, SecP256K1Curve.q);
    maybeEnableNative();
  }

  @Override
  public void disableNative() {
    useNative = false;
  }

  @Override
  public boolean maybeEnableNative() {
    try {
      // Check if LibSecp256k1Graal context is available
      // Must use isNonNull() for Word types, not comparison to null
      if (LibSecp256k1Graal.getContext().isNonNull()) {
        LOG.info("Using GraalVM-compatible native secp256k1 implementation");
      }
    } catch (UnsatisfiedLinkError | NoClassDefFoundError e) {
      LOG.info("GraalVM native secp256k1 not available - {}", e.getMessage());
      useNative = false;
    }
    return useNative;
  }

  @Override
  public boolean isNative() {
    return useNative;
  }

  @Override
  public DSAKCalculator getKCalculator() {
    return new HMacDSAKCalculator(new SHA256Digest());
  }

  @Override
  public SECPSignature sign(final Bytes32 dataHash, final KeyPair keyPair) {
    if (useNative) {
      return signNative(dataHash, keyPair);
    } else {
      return super.sign(dataHash, keyPair);
    }
  }

  @Override
  public boolean verify(final Bytes data, final SECPSignature signature, final SECPPublicKey pub) {
    if (useNative) {
      return verifyNative(data, signature, pub);
    } else {
      return super.verify(data, signature, pub);
    }
  }

  @Override
  public Optional<SECPPublicKey> recoverPublicKeyFromSignature(
      final Bytes32 dataHash, final SECPSignature signature) {
    if (useNative) {
      Optional<SECPPublicKey> result = recoverFromSignatureNative(dataHash, signature);
      if (result.isEmpty()) {
        throw new IllegalArgumentException("Could not recover public key");
      } else {
        return result;
      }
    } else {
      return super.recoverPublicKeyFromSignature(dataHash, signature);
    }
  }

  @Override
  public String getCurveName() {
    return CURVE_NAME;
  }

  @Override
  protected BigInteger recoverFromSignature(
      final int recId, final BigInteger r, final BigInteger s, final Bytes32 dataHash) {
    if (useNative) {
      return recoverFromSignatureNative(dataHash, new SECPSignature(r, s, (byte) recId))
          .map(key -> new BigInteger(1, key.getEncoded()))
          .orElse(null);
    } else {
      return super.recoverFromSignature(recId, r, s, dataHash);
    }
  }

  private SECPSignature signNative(final Bytes32 dataHash, final KeyPair keyPair) {
    final byte[] privateKeyBytes = keyPair.getPrivateKey().getEncoded();
    final byte[] messageBytes = dataHash.toArrayUnsafe();

    // Sign using GraalVM-compatible library
    final byte[] signature =
        LibSecp256k1Graal.ecdsaSignRecoverable(
            LibSecp256k1Graal.getContext(), privateKeyBytes, messageBytes);

    if (signature == null || signature.length != 65) {
      throw new RuntimeException(
          "Could not natively sign. Private Key is invalid or signature generation failed.");
    }

    // signature is 65 bytes: 64 bytes compact (r + s) + 1 byte recId
    final Bytes32 r = Bytes32.wrap(signature, 0);
    final Bytes32 s = Bytes32.wrap(signature, 32);
    final byte recId = signature[64];

    return SECPSignature.create(
        r.toUnsignedBigInteger(), s.toUnsignedBigInteger(), recId, curveOrder);
  }

  private boolean verifyNative(
      final Bytes data, final SECPSignature signature, final SECPPublicKey pub) {
    try {
      // Parse public key (need to add 0x04 prefix for uncompressed format)
      final Bytes encodedPubKey = Bytes.concatenate(Bytes.of(0x04), pub.getEncodedBytes());

      final byte[] pubkeyInternal = new byte[64];
      final int parseResult =
          LibSecp256k1Graal.ecPubkeyParse(
              LibSecp256k1Graal.getContext(), pubkeyInternal, encodedPubKey.toArrayUnsafe());

      if (parseResult != 1) {
        throw new IllegalArgumentException("Could not parse public key");
      }

      // Verify signature (use only r and s, not recovery ID)
      final byte[] compactSignature = signature.encodedBytes().slice(0, 64).toArrayUnsafe();

      return LibSecp256k1Graal.ecdsaVerify(
              LibSecp256k1Graal.getContext(), compactSignature, data.toArrayUnsafe(), pubkeyInternal)
          != 0;
    } catch (final Exception e) {
      LOG.error("Native verification failed", e);
      return false;
    }
  }

  private Optional<SECPPublicKey> recoverFromSignatureNative(
      final Bytes32 dataHash, final SECPSignature signature) {
    try {
      // Use the compact signature + recId version
      final byte[] compactSignature = signature.encodedBytes().slice(0, 64).toArrayUnsafe();
      final int recId = signature.getRecId();

      final byte[] recoveredPubkey =
          LibSecp256k1Graal.ecdsaRecover(
              LibSecp256k1Graal.getContext(), compactSignature, dataHash.toArrayUnsafe(), recId);

      if (recoveredPubkey == null) {
        return Optional.empty();
      }

      // The recovered pubkey is already in internal 64-byte format
      // Serialize to uncompressed format (65 bytes with 0x04 prefix)
      final byte[] serialized =
          LibSecp256k1Graal.ecPubkeySerialize(
              LibSecp256k1Graal.getContext(), recoveredPubkey, false);

      if (serialized == null || serialized.length != 65) {
        return Optional.empty();
      }

      // Remove the 0x04 prefix to get the 64-byte public key
      return Optional.of(SECPPublicKey.create(Bytes.wrap(serialized).slice(1), ALGORITHM));
    } catch (final Exception e) {
      LOG.error("Native recovery failed", e);
      return Optional.empty();
    }
  }
}
