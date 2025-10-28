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

import static org.hyperledger.besu.ethereum.trie.pathbased.common.storage.PathBasedWorldStateKeyValueStorage.WORLD_BLOCK_HASH_KEY;
import static org.hyperledger.besu.ethereum.trie.pathbased.common.storage.PathBasedWorldStateKeyValueStorage.WORLD_ROOT_HASH_KEY;

import org.hyperledger.besu.config.GenesisConfig;
import org.hyperledger.besu.consensus.merge.PostMergeContext;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.BlockProcessingResult;
import org.hyperledger.besu.ethereum.ProtocolContext;
import org.hyperledger.besu.ethereum.chain.BadBlockManager;
import org.hyperledger.besu.ethereum.chain.DefaultBlockchain;
import org.hyperledger.besu.ethereum.chain.GenesisState;
import org.hyperledger.besu.ethereum.chain.MutableBlockchain;
import org.hyperledger.besu.ethereum.core.Block;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.Difficulty;
import org.hyperledger.besu.ethereum.core.MiningConfiguration;
import org.hyperledger.besu.ethereum.mainnet.HeaderValidationMode;
import org.hyperledger.besu.ethereum.mainnet.MainnetBlockHeaderFunctions;
import org.hyperledger.besu.ethereum.mainnet.MainnetProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpec;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.storage.StorageProvider;
import org.hyperledger.besu.ethereum.storage.keyvalue.KeyValueSegmentIdentifier;
import org.hyperledger.besu.ethereum.storage.keyvalue.KeyValueStoragePrefixedKeyBlockchainStorage;
import org.hyperledger.besu.ethereum.storage.keyvalue.KeyValueStorageProvider;
import org.hyperledger.besu.ethereum.storage.keyvalue.VariablesKeyValueStorage;
import org.hyperledger.besu.ethereum.trie.pathbased.bonsai.BonsaiWorldStateProvider;
import org.hyperledger.besu.ethereum.trie.pathbased.bonsai.cache.CodeCache;
import org.hyperledger.besu.ethereum.trie.pathbased.bonsai.cache.NoopBonsaiCachedMerkleTrieLoader;
import org.hyperledger.besu.ethereum.trie.pathbased.bonsai.storage.BonsaiWorldStateKeyValueStorage;
import org.hyperledger.besu.ethereum.worldstate.DataStorageConfiguration;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.metrics.noop.NoOpMetricsSystem;
import org.hyperledger.besu.plugin.ServiceManager;
import org.hyperledger.besu.plugin.services.BesuService;
import org.hyperledger.besu.riscv.poc.crypto.SECP256K1Graal;
import org.hyperledger.besu.services.kvstore.InMemoryKeyValueStorage;
import org.hyperledger.besu.services.kvstore.SegmentedInMemoryKeyValueStorage;

import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tuweni.bytes.Bytes;

public class BlockRunner {

  private final ProtocolSchedule protocolSchedule;
  private final MutableBlockchain blockchain;
  private final ProtocolContext protocolContext;

  /**
   * Record to hold command line arguments for file paths.
   *
   * @param stateJsonPath Optional path to state.json file
   * @param blockRlpPath Optional path to block.rlp file
   * @param genesisConfigPath Optional path to genesis config file
   */
  private record CommandLineArgs(
      Optional<String> stateJsonPath,
      Optional<String> blockRlpPath,
      Optional<String> genesisConfigPath) {}

  private static final NoOpMetricsSystem noOpMetricsSystem = new NoOpMetricsSystem();

  // Configure the EVM with in-memory (stacked) world updater mode.
  private static final EvmConfiguration evmConfiguration =
      new EvmConfiguration(
          EvmConfiguration.DEFAULT.jumpDestCacheWeightKB(),
          EvmConfiguration.WorldUpdaterMode.STACKED,
          true);
  /*

    /**
     * Factory method that builds a complete in-memory Besu execution environment. It imports previous
     * headers, reconstructs the world state from a witness, and returns a {@link BlockRunner} ready
     * to process a block.
     */
  public static BlockRunner create(
      final BlockHeader targetBlockHeader,
      final List<BlockHeader> prevHeaders,
      final Map<Hash, Bytes> trieNodes,
      final Map<Hash, Bytes> codes,
      final String genesisConfigJson) {

    final GenesisConfig genesisConfig = GenesisConfig.fromConfig(genesisConfigJson);

    // use a minimal protocol schedule:
    final ProtocolSchedule protocolSchedule = constructMinimalConfig(genesisConfig, targetBlockHeader);

    //TODO: possibly make minimal vs mainnet protocol schedule configurable
//    // or use the mainnet-derived protocol schedule
//    final ProtocolSchedule protocolSchedule = constructFromGenesisConfig(genesisConfig);

    // Construct the genesis state and world state root.
    final GenesisState genesisState =
        GenesisState.fromConfig(genesisConfig, protocolSchedule, new CodeCache());

    // Create an in-memory key-value storage provider.
    final StorageProvider storageProvider =
        new KeyValueStorageProvider(
            segments -> new SegmentedInMemoryKeyValueStorage(),
            new InMemoryKeyValueStorage(),
            noOpMetricsSystem);

    // Blockchain storage setup (headers, blocks, variables).
    final var variablesStorage =
        new VariablesKeyValueStorage(
            storageProvider.getStorageBySegmentIdentifier(KeyValueSegmentIdentifier.VARIABLES));
    final var blockchainStorage =
        new KeyValueStoragePrefixedKeyBlockchainStorage(
            storageProvider.getStorageBySegmentIdentifier(KeyValueSegmentIdentifier.BLOCKCHAIN),
            variablesStorage,
            new MainnetBlockHeaderFunctions(),
            false);

    final MutableBlockchain blockchain =
        DefaultBlockchain.createMutable(
            genesisState.getBlock(), blockchainStorage, noOpMetricsSystem, 0);

    // Import all previous headers into the blockchain storage and set the chain head.
    final KeyValueStoragePrefixedKeyBlockchainStorage.Updater updater = blockchainStorage.updater();
    final BlockHeader head = importHeadersAndSetHead(prevHeaders, updater);
    updater.commit();

    // Prepare a Bonsai world state layer using stateless storage (no persistence).
    var bonsaiStorage =
        new StatelessBonsaiWorldStateLayerStorage(
            storageProvider,
            noOpMetricsSystem,
            DataStorageConfiguration.DEFAULT_BONSAI_PARTIAL_DB_CONFIG);

    // Dummy ServiceManager since no external services are used here.
    final ServiceManager serviceManager =
        new ServiceManager() {
          @Override
          public <T extends BesuService> void addService(Class<T> serviceType, T service) {
            // no nop
          }

          @Override
          public <T extends BesuService> Optional<T> getService(Class<T> serviceType) {
            return Optional.empty();
          }
        };

    // Populate trie nodes and contract code into the world state.
    final BonsaiWorldStateKeyValueStorage.Updater stateUpdater = bonsaiStorage.updater();
    trieNodes.forEach(
        (hash, value) -> {
          stateUpdater
              .getWorldStateTransaction()
              .put(KeyValueSegmentIdentifier.TRIE_BRANCH_STORAGE, hash.toArray(), value.toArray());
        });
    codes.forEach(
        (hash, value) -> {
          stateUpdater
              .getWorldStateTransaction()
              .put(
                  KeyValueSegmentIdentifier.CODE_STORAGE,
                  hash.toArrayUnsafe(),
                  value.toArrayUnsafe());
        });
    stateUpdater
        .getWorldStateTransaction()
        .put(
            KeyValueSegmentIdentifier.TRIE_BRANCH_STORAGE,
            WORLD_ROOT_HASH_KEY,
            head.getStateRoot().toArray());
    stateUpdater
        .getWorldStateTransaction()
        .put(
            KeyValueSegmentIdentifier.TRIE_BRANCH_STORAGE,
            WORLD_BLOCK_HASH_KEY,
            head.getBlockHash().toArray());
    stateUpdater.commit();

    // Create a world state provider using Bonsai implementation.
    final var worldStateArchive =
        new BonsaiWorldStateProvider(
            bonsaiStorage,
            blockchain,
            Optional.empty(), // maxLayersToLoad
            new NoopBonsaiCachedMerkleTrieLoader(),
            serviceManager,
            evmConfiguration,
            () -> (__, ___) -> {},
            new CodeCache());

    /*
    curl --location 'http://127.0.0.1:8545' \
    --data '{
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [
            "0xca36c1e529714639c25fc2ac9a3b13c4d0a3e81a74f451313ec2926c54cc48f3",
            {
                "disableStorage": true
            }
        ],
        "id": 1
    }'
     */

    // Build a lightweight ProtocolContext used to execute blocks.
    final var postMergeContext = new PostMergeContext();
    final var protocolContext =
        new ProtocolContext.Builder()
            .withBlockchain(blockchain)
            .withWorldStateArchive(worldStateArchive)
            .withConsensusContext(postMergeContext)
            .withBadBlockManager(new BadBlockManager())
            .withServiceManager(serviceManager)
            .build();

    // The MinimalProtocolSchedule already created the correct precompile registry
    // with Graal-native implementations, so no additional decoration is needed.
    return new BlockRunner(protocolSchedule, protocolContext, blockchain);
  }

  /**
   * Imports a list of ordered block headers into blockchain storage, validates parent linkage, sets
   * the chain head to the last header, and returns it.
   */
  private static BlockHeader importHeadersAndSetHead(
      final List<BlockHeader> headers,
      final KeyValueStoragePrefixedKeyBlockchainStorage.Updater updater) {
    if (headers == null || headers.isEmpty()) {
      throw new IllegalArgumentException("Header list cannot be null or empty");
    }
    BlockHeader previous = headers.getFirst();
    Hash previousHash = previous.getHash();
    // Store the first header
    updater.putBlockHeader(previousHash, previous);
    updater.putBlockHash(previous.getNumber(), previousHash);
    // Process the rest of the chain and verify parent linkage.
    for (int i = 1; i < headers.size(); i++) {
      final BlockHeader current = headers.get(i);
      if (!current.getParentHash().equals(previousHash)) {
        throw new IllegalStateException(
            String.format(
                "Invalid block header chain at index %d: expected parent %s, got %s",
                i, previousHash, current.getParentHash()));
      }
      previous = current;
      previousHash = current.getHash();
      updater.putBlockHeader(previousHash, previous);
      updater.putBlockHash(previous.getNumber(), previousHash);
    }
    // Set the final header as the chain head and initialize total difficulty.
    updater.setChainHead(previousHash);
    updater.putTotalDifficulty(previousHash, Difficulty.ZERO);
    return previous;
  }

  private BlockRunner(
      ProtocolSchedule protocolSchedule,
      ProtocolContext protocolContext,
      MutableBlockchain blockchain) {
    this.protocolSchedule = protocolSchedule;
    this.protocolContext = protocolContext;
    this.blockchain = blockchain;
  }

  /**
   * Validates and executes a single block against the reconstructed blockchain and world state.
   *
   * <p>Workflow: 1) Lookup the ProtocolSpec for the block header (selects the correct
   * rules/processor). 2) Run validateAndProcessBlock(): - validates the header (FULL) and body
   * (NONE for ommers here), - executes all transactions against the current world state, -
   * generates receipts and computes the resulting state root, - verifies that the computed state
   * root matches the header’s stateRoot. 3) If successful, append the block and receipts to the
   * in-memory blockchain. 4) If validation fails, print the error and throw.
   *
   * <p>Notes: - result.getYield() is optional; use orElseThrow() to make failures explicit when
   * printing. - Consider replacing System.out with a logger for real usage.
   *
   * @param block the block to validate and execute
   * @throws RuntimeException if validation or execution fails
   */
  public void processBlock(final Block block) {

    final ProtocolSpec protocolSpec = protocolSchedule.getByBlockHeader(block.getHeader());

    System.out.println("Starting block execution...");
    final long blockStartTime = System.nanoTime();

    final BlockProcessingResult result =
        protocolSpec
            .getBlockValidator()
            .validateAndProcessBlock(
                protocolContext,
                block,
                HeaderValidationMode.FULL,
                HeaderValidationMode.NONE,
                true,
                false);

    final long blockEndTime = System.nanoTime();
    final double blockExecutionTimeMs = (blockEndTime - blockStartTime) / 1_000_000.0;

    if (!result.isSuccessful()) {
      System.out.println(
          "Block "
              + block.getHeader().getNumber()
              + " failed with error message "
              + result.errorMessage);
      throw new RuntimeException("Block processing failed");
    }

    blockchain.appendBlock(block, result.getReceipts());

    System.out.println("✓ Block " + block.getHeader().getNumber() + " processed successfully");
    System.out.println("  Transactions: " + block.getBody().getTransactions().size());
    System.out.println("  Receipts: " + result.getReceipts().size());
    System.out.println("  Gas used: " + block.getHeader().getGasUsed());
    System.out.println(String.format("  Block execution time: %.2f ms", blockExecutionTimeMs));
    System.out.println("  Stateroot: " + result.getYield().get().getWorldState().rootHash());
  }

  private static ProtocolSchedule constructMinimalConfig(
      GenesisConfig genesisConfig,
      BlockHeader targetBlockHeader) {
    return MinimalProtocolSchedule.create(
            targetBlockHeader,
            genesisConfig,
            evmConfiguration,
            new BadBlockManager(),
            noOpMetricsSystem);

  }

  private static ProtocolSchedule constructFromGenesisConfig(
      final GenesisConfig genesisConfig) {
    // Build the mainnet protocol schedule based on the genesis config.
    return
        MainnetProtocolSchedule.fromConfig(
            genesisConfig.getConfigOptions(),
            evmConfiguration,
            MiningConfiguration.MINING_DISABLED,
            new BadBlockManager(),
            false,
            false,
            noOpMetricsSystem);


  }
  /** Print usage information and exit. */
  private static void printUsageAndExit() {
    System.out.println("Usage: BlockRunner [OPTIONS]");
    System.out.println();
    System.out.println("Options:");
    System.out.println("  --state=<path>    Path to state.json file");
    System.out.println("  --block=<path>    Path to block.rlp file");
    System.out.println("  --genesis=<path>  Path to genesis config file");
    System.out.println("                    /mainnet.json, /sepolia.json, and /hoodi.json");
    System.out.println("                    are bundled. ");
    System.out.println("  --help, -h, ?     Display this help message");
    System.out.println();
    System.out.println("Defaults:");
    System.out.println("  --state   : bundled /state.json resource");
    System.out.println("  --block   : bundled /block.rlp resource");
    System.out.println("  --genesis : bundled /mainnet.json resource");
    System.exit(0);
  }

  /**
   * Parse command line arguments for state, block, and genesis file paths.
   *
   * @param args command line arguments
   * @return CommandLineArgs record with optional file paths
   */
  private static CommandLineArgs parseArguments(final String[] args) {
    Optional<String> stateJsonPath = Optional.empty();
    Optional<String> blockRlpPath = Optional.empty();
    Optional<String> genesisConfigPath = Optional.empty();

    // Parse named arguments
    for (String arg : args) {
      if (arg.equals("--help") || arg.equals("-h") || arg.equals("?")) {
        printUsageAndExit();
      } else if (arg.startsWith("--state=")) {
        stateJsonPath = Optional.of(arg.substring("--state=".length()));
      } else if (arg.startsWith("--block=")) {
        blockRlpPath = Optional.of(arg.substring("--block=".length()));
      } else if (arg.startsWith("--genesis=")) {
        genesisConfigPath = Optional.of(arg.substring("--genesis=".length()));
      } else {
        System.err.println("Unknown argument: " + arg);
        System.err.println("Use --help for usage information");
        System.exit(1);
      }
    }
    return new CommandLineArgs(stateJsonPath, blockRlpPath, genesisConfigPath);
  }

  /**
   * Load file content from either classpath resource or filesystem path. Tries classpath resource
   * first, then falls back to filesystem if not found.
   *
   * @param filePath Optional filesystem path or resource path
   * @param defaultResourcePath default classpath resource path (e.g., "/state.json")
   * @return file content as string
   */
  private static String loadFileContent(
      final Optional<String> filePath, final String defaultResourcePath) throws Exception {
    String path = filePath.orElse(defaultResourcePath);

    // Try loading from classpath resource first
    try (var inputStream = BlockRunner.class.getResourceAsStream(path)) {
      if (inputStream != null) {
        System.out.println("Loading from classpath: " + path);
        return new String(inputStream.readAllBytes(), Charset.defaultCharset());
      }
    }
    // Fall back to filesystem
    System.out.println("Loading from filesystem: " + path);
    return Files.readString(Path.of(path));
  }

  public static void main(final String[] args) {
    final long programStartTime = System.nanoTime();

    System.out.println("Starting BlockRunner .");
    CommandLineArgs cmdArgs = parseArguments(args);

    // set graal signature algorithm:
    SignatureAlgorithm graalSig = new SECP256K1Graal();
    graalSig.maybeEnableNative();
    SignatureAlgorithmFactory.setInstance(graalSig);

    try {
      ObjectMapper objectMapper = new ObjectMapper();

      // Load genesis config
      String genesisConfigJson = loadFileContent(cmdArgs.genesisConfigPath(), "/mainnet.json");
      System.out.println("✓ Loaded genesis config");

      /*
         curl --location 'http://127.0.0.1:8545' --data '{
             "jsonrpc": "2.0",
             "method": "debug_executionWitness",
             "params": [
                 "0xC9B0"
             ],
             "id": 1
         }'
      */
      String stateJsonContent = loadFileContent(cmdArgs.stateJsonPath(), "/state.json");
      ExecutionWitnessJson executionWitness =
          objectMapper.readValue(stateJsonContent, ExecutionWitnessJson.class);
      System.out.println("✓ Loaded execution witness");
      System.out.println("  State: " + executionWitness.getState().size());
      System.out.println("  Keys: " + executionWitness.getKeys().size());
      System.out.println("  Codes: " + executionWitness.getCodes().size());
      System.out.println("  Headers: " + executionWitness.getHeaders().size());

      final Map<Hash, Bytes> trieNodes =
          executionWitness.getState().stream()
              .map(Bytes::fromHexString)
              .collect(Collectors.toMap(Hash::hash, o -> o));
      final Map<Hash, Bytes> codes =
          executionWitness.getCodes().stream()
              .map(Bytes::fromHexString)
              .collect(Collectors.toMap(Hash::hash, o -> o));

      /*
         curl --location 'http://127.0.0.1:8545' --data '{
             "jsonrpc": "2.0",
             "method": "debug_getRawBlock",
             "params": [
                 "0xC9B0"
             ],
             "id": 1
         }'
      */
      String blockRlpContent = loadFileContent(cmdArgs.blockRlpPath(), "/block.rlp");
      Block blockToImport =
          Block.readFrom(
              RLP.input(Bytes.fromHexString(blockRlpContent.trim())),
              new MainnetBlockHeaderFunctions());
      System.out.println("✓ Loaded block to import " + blockToImport.getHeader().getNumber());

      final List<BlockHeader> previousHeaders =
          executionWitness.getHeaders().stream()
              .map(
                  s ->
                      BlockHeader.readFrom(
                          RLP.input(Bytes.fromHexString(s)), new MainnetBlockHeaderFunctions()))
              .sorted(Comparator.comparing(BlockHeader::getNumber))
              .toList();

      final long setupEndTime = System.nanoTime();
      final double setupTimeMs = (setupEndTime - programStartTime) / 1_000_000.0;
      System.out.println(String.format("\n✓ Setup completed in %.2f ms\n", setupTimeMs));

      final BlockRunner runner =
          BlockRunner.create(
              blockToImport.getHeader(), previousHeaders, trieNodes, codes, genesisConfigJson);

      runner.processBlock(blockToImport);

      final long programEndTime = System.nanoTime();
      final double totalTimeMs = (programEndTime - programStartTime) / 1_000_000.0;
      final double blockProcessingTimeMs = totalTimeMs - setupTimeMs;

      System.out.println("\n" + "=".repeat(60));
      System.out.println("TIMING SUMMARY");
      System.out.println("=".repeat(60));
      System.out.println(String.format("  Setup time:           %.2f ms", setupTimeMs));
      System.out.println(String.format("  Block processing:     %.2f ms", blockProcessingTimeMs));
      System.out.println(String.format("  Total program time:   %.2f ms", totalTimeMs));
      System.out.println("=".repeat(60));

    } catch (Exception e) {
      System.err.println("Error loading or processing block: " + e.getMessage());
      e.printStackTrace();
      System.exit(1);
    }
  }
}
