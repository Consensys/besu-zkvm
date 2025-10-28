/*
 * Copyright Consensys Software Inc., 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.hyperledger.besu.riscv.poc.block.execution;

import org.hyperledger.besu.config.GenesisConfig;
import org.hyperledger.besu.config.GenesisConfigOptions;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.ethereum.chain.BadBlockManager;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.MiningConfiguration;
import org.hyperledger.besu.ethereum.mainnet.MainnetProtocolSpecFactory;
import org.hyperledger.besu.ethereum.mainnet.PrecompiledContractConfiguration;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpec;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpecBuilder;
import org.hyperledger.besu.ethereum.mainnet.blockhash.CancunPreExecutionProcessor;
import org.hyperledger.besu.ethereum.mainnet.blockhash.FrontierPreExecutionProcessor;
import org.hyperledger.besu.ethereum.mainnet.blockhash.PraguePreExecutionProcessor;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.evm.precompile.MainnetPrecompiledContracts;
import org.hyperledger.besu.evm.precompile.PrecompileContractRegistry;
import org.hyperledger.besu.plugin.services.MetricsSystem;
import org.hyperledger.besu.riscv.poc.evm.precompiles.GraalAltBN128AddPrecompiledContract;
import org.hyperledger.besu.riscv.poc.evm.precompiles.GraalAltBN128MulPrecompiledContract;
import org.hyperledger.besu.riscv.poc.evm.precompiles.GraalAltBN128PairingPrecompiledContract;
import org.hyperledger.besu.riscv.poc.evm.precompiles.GraalECRECPrecompiledContract;
import org.hyperledger.besu.riscv.poc.evm.precompiles.MockPrecompiledContract;

import java.math.BigInteger;
import java.util.Optional;
import java.util.OptionalInt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Minimal protocol schedule that creates only a single ProtocolSpec for the target block's fork.
 *
 * <p>This avoids the overhead of building protocol specs for all forks from Frontier through the
 * latest, and immediately uses GraalVM-native precompiles instead of creating JNA-based ones that
 * are later replaced.
 */
public class MinimalProtocolSchedule {

  private static final Logger LOG = LoggerFactory.getLogger(MinimalProtocolSchedule.class);

  /**
   * Create a minimal protocol schedule for a single target block.
   *
   * @param targetHeader the block header being processed
   * @param genesisConfig the genesis configuration
   * @param evmConfiguration the EVM configuration
   * @param badBlockManager the bad block manager
   * @param metricsSystem the metrics system
   * @return a protocol schedule with only the necessary fork spec
   */
  public static ProtocolSchedule create(
      final BlockHeader targetHeader,
      final GenesisConfig genesisConfig,
      final EvmConfiguration evmConfiguration,
      final BadBlockManager badBlockManager,
      final MetricsSystem metricsSystem) {

    final GenesisConfigOptions configOptions = genesisConfig.getConfigOptions();
    final Optional<BigInteger> chainId =
        configOptions.getChainId().or(() -> Optional.of(BigInteger.ONE));

    // Determine which fork applies to this block
    final long timestamp = targetHeader.getTimestamp();
    final ForkInfo forkInfo = determineFork(timestamp, configOptions);

    LOG.info(
        "Creating minimal protocol schedule for fork: {} at timestamp: {}",
        forkInfo.name(),
        timestamp);

    // Create the protocol spec factory
    final MainnetProtocolSpecFactory specFactory =
        new MainnetProtocolSpecFactory(
            chainId,
            false, // isRevertReasonEnabled
            configOptions,
            evmConfiguration.overrides(
                configOptions.getContractSizeLimit(),
                OptionalInt.empty(),
                configOptions.getEvmStackSize()),
            MiningConfiguration.MINING_DISABLED,
            false, // isParallelTxProcessingEnabled
            false, // isBlockAccessListEnabled
            metricsSystem);

    // Get the protocol spec builder for the target fork
    final ProtocolSpecBuilder builder = forkInfo.getSpecBuilder(specFactory);

    // Replace the precompile registry builder with one that creates Graal implementations
    builder.precompileContractRegistryBuilder(
        MinimalProtocolSchedule::createGraalPrecompileRegistry);
    builder.badBlocksManager(badBlockManager);

    // set the appropriate pre-execution processor
    // The fork definitions SHOULD set this, but we explicitly set it as a safety measure
    // to prevent NullPointerException in AbstractBlockProcessor.processBlock
    ensurePreExecutionProcessor(builder, forkInfo.name());

    LOG.info("Building ProtocolSpec for fork: {}", forkInfo.name());

    // Create a single-spec protocol schedule with null spec initially
    // This avoids DefaultProtocolSchedule's preconditions (milestone at block 0, sorted sets, etc.)
    // The spec will be set after building to resolve the circular dependency
    final SingleSpecProtocolSchedule protocolSchedule =
        new SingleSpecProtocolSchedule(null, chainId);

    // Build the protocol spec, passing the schedule (which will be populated below)
    final ProtocolSpec spec = builder.build(protocolSchedule);

    // Now set the spec in the schedule to resolve the circular dependency
    protocolSchedule.setProtocolSpec(spec);

    return protocolSchedule;
  }

  /**
   * Ensure the ProtocolSpecBuilder has the appropriate PreExecutionProcessor set for the fork.
   *
   * @param builder the protocol spec builder
   * @param forkName the name of the fork (Paris, Shanghai, Cancun, Prague, Osaka)
   */
  private static void ensurePreExecutionProcessor(
      final ProtocolSpecBuilder builder, final String forkName) {
    switch (forkName) {
      case "Prague", "Osaka" -> builder.preExecutionProcessor(new PraguePreExecutionProcessor());
      default -> builder.preExecutionProcessor(new FrontierPreExecutionProcessor());
    }
  }

  /**
   * Create a precompile registry populated with GraalVM-native implementations.
   *
   * <p>This builds the registry from scratch using only Graal-compatible implementations to avoid
   * triggering static initializers in JNA-based precompile classes.
   *
   * @param config the precompiled contract configuration (contains gas calculator)
   * @return a precompile registry with Graal implementations
   */
  private static PrecompileContractRegistry createGraalPrecompileRegistry(
      final PrecompiledContractConfiguration config) {

    final GasCalculator gasCalculator = config.getGasCalculator();

    // Start with Frontier precompiles (pure Java, no native dependencies)
    // This creates ECREC, SHA256, RIPEMD160, ID without triggering AltBN128 static initializers
    final PrecompileContractRegistry registry = MainnetPrecompiledContracts.frontier(gasCalculator);

    // Replace ECREC with our Graal version
    registry.put(Address.ECREC, new GraalECRECPrecompiledContract(gasCalculator));

    // Add Byzantium precompiles
    // TODO: Add MODEXP if needed (pure Java, needs reflection or package relocation)
    // registry.put(Address.MODEXP, ...);

    // Use our Graal-native AltBN128 implementations (avoid Besu's JNA-based ones)
    registry.put(Address.ALTBN128_ADD, new GraalAltBN128AddPrecompiledContract(gasCalculator));
    registry.put(Address.ALTBN128_MUL, new GraalAltBN128MulPrecompiledContract(gasCalculator));
    registry.put(
        Address.ALTBN128_PAIRING, new GraalAltBN128PairingPrecompiledContract(gasCalculator));

    // Add Byzantium MODEXP as mock (pure Java, but needs package access workaround)
    registry.put(Address.MODEXP, new MockPrecompiledContract("MODEXP", gasCalculator));

    // Add Istanbul BLAKE2BF as mock
    registry.put(
        Address.BLAKE2B_F_COMPRESSION,
        new MockPrecompiledContract("BLAKE2B_F_COMPRESSION", gasCalculator));

    // Add Cancun KZG_POINT_EVAL as mock (EIP-4844)
    registry.put(
        Address.KZG_POINT_EVAL, new MockPrecompiledContract("KZG_POINT_EVAL", gasCalculator));

    // Add Prague BLS12-381 precompiles as mocks (EIP-2537)
    registry.put(Address.BLS12_G1ADD, new MockPrecompiledContract("BLS12_G1ADD", gasCalculator));
    registry.put(
        Address.BLS12_G1MULTIEXP,
        new MockPrecompiledContract("BLS12_G1MULTIEXP", gasCalculator));
    registry.put(Address.BLS12_G2ADD, new MockPrecompiledContract("BLS12_G2ADD", gasCalculator));
    registry.put(
        Address.BLS12_G2MULTIEXP,
        new MockPrecompiledContract("BLS12_G2MULTIEXP", gasCalculator));
    registry.put(
        Address.BLS12_PAIRING, new MockPrecompiledContract("BLS12_PAIRING", gasCalculator));
    registry.put(
        Address.BLS12_MAP_FP_TO_G1,
        new MockPrecompiledContract("BLS12_MAP_FP_TO_G1", gasCalculator));
    registry.put(
        Address.BLS12_MAP_FP2_TO_G2,
        new MockPrecompiledContract("BLS12_MAP_FP2_TO_G2", gasCalculator));

    return registry;
  }

  /**
   * Determine which fork applies to the given timestamp.
   *
   * @param timestamp the block timestamp
   * @param config the genesis config options
   * @return the fork info
   */
  private static ForkInfo determineFork(final long timestamp, final GenesisConfigOptions config) {
    // Check timestamp-based forks in reverse chronological order (newest first)
    if (config.getOsakaTime().isPresent() && timestamp >= config.getOsakaTime().getAsLong()) {
      return new ForkInfo(
          "Osaka",
          config.getOsakaTime().getAsLong(),
          true,
          MainnetProtocolSpecFactory::osakaDefinition);
    }
    if (config.getPragueTime().isPresent() && timestamp >= config.getPragueTime().getAsLong()) {
      return new ForkInfo(
          "Prague",
          config.getPragueTime().getAsLong(),
          true,
          MainnetProtocolSpecFactory::pragueDefinition);
    }
    if (config.getCancunTime().isPresent() && timestamp >= config.getCancunTime().getAsLong()) {
      return new ForkInfo(
          "Cancun",
          config.getCancunTime().getAsLong(),
          true,
          MainnetProtocolSpecFactory::cancunDefinition);
    }
    if (config.getShanghaiTime().isPresent() && timestamp >= config.getShanghaiTime().getAsLong()) {
      return new ForkInfo(
          "Shanghai",
          config.getShanghaiTime().getAsLong(),
          true,
          MainnetProtocolSpecFactory::shanghaiDefinition);
    }

    // Default to Paris (The Merge) for post-merge blocks
    // This is reasonable since the user stated this only processes blocks SINCE Paris
    return new ForkInfo("Paris", 0L, false, MainnetProtocolSpecFactory::parisDefinition);
  }

  /** Information about a fork and how to build its protocol spec. */
  private record ForkInfo(
      String name,
      long activationValue,
      boolean isTimestampBased,
      SpecBuilderFunction getSpecBuilder) {

    ProtocolSpecBuilder getSpecBuilder(final MainnetProtocolSpecFactory factory) {
      return getSpecBuilder.apply(factory);
    }
  }

  /** Functional interface for getting a protocol spec builder from a factory. */
  @FunctionalInterface
  private interface SpecBuilderFunction {
    ProtocolSpecBuilder apply(MainnetProtocolSpecFactory factory);
  }
}
