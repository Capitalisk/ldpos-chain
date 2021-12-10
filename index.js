const crypto = require('crypto');
const path = require('path');
const shuffle = require('lodash.shuffle');
const WritableConsumableStream = require('writable-consumable-stream');

const genesisBlock = require('./genesis/testnet/genesis.json');
const pkg = require('./package.json');

const { validateBlockSchema } = require('./schemas/block-schema');
const { validateTransactionSchema } = require('./schemas/transaction-schema');
const { validateBlockSignatureSchema } = require('./schemas/block-signature-schema');
const { validateMultisigTransactionSchema } = require('./schemas/multisig-transaction-schema');
const { validateSigTransactionSchema } = require('./schemas/sig-transaction-schema');
const {
  validateWalletAddress,
  validateBlockId,
  validateBlockHeight,
  validateTransactionId,
  validateTimestamp,
  validateOffset,
  validateLimit,
  validateSortOrder
} = require('./schemas/primitives');

const {
  LDPOS_PASSWORD,
  LDPOS_FORGING_KEY_INDEX
} = process.env;

const CIPHER_ALGORITHM = 'aes-192-cbc';
const CIPHER_KEY = LDPOS_PASSWORD ? crypto.scryptSync(LDPOS_PASSWORD, 'salt', 24) : undefined;
const CIPHER_IV = Buffer.alloc(16, 0);

const DEFAULT_MODULE_ALIAS = 'ldpos_chain';
const DEFAULT_GENESIS_PATH = path.resolve(__dirname, './genesis/mainnet/genesis.json');
const DEFAULT_NETWORK_SYMBOL = 'ldpos';
const DEFAULT_CRYPTO_CLIENT_LIB_PATH = 'ldpos-client';
const DEFAULT_FORGER_COUNT = 15;
const DEFAULT_MIN_FORGER_BLOCK_SIGNATURE_RATIO = .6;
const DEFAULT_FORGING_INTERVAL = 30000;
const DEFAULT_FETCH_BLOCK_LIMIT = 10;
const DEFAULT_FETCH_BLOCK_PAUSE = 500;
const DEFAULT_BLOCK_PROCESSING_FAILURE_PAUSE = 20000;
const DEFAULT_FETCH_BLOCK_END_CONFIRMATIONS = 10;
const DEFAULT_FORGING_BLOCK_BROADCAST_DELAY = 2000;
const DEFAULT_FORGING_SIGNATURE_BROADCAST_DELAY = 8000;
const DEFAULT_AUTO_SYNC_FORGING_KEY_INDEX = true;
const DEFAULT_PROPAGATION_TIMEOUT = 7000;
const DEFAULT_PROPAGATION_RANDOMNESS = 5000;
const DEFAULT_TIME_POLL_INTERVAL = 200;
const DEFAULT_MIN_TRANSACTIONS_PER_BLOCK = 1;
const DEFAULT_MAX_TRANSACTIONS_PER_BLOCK = 300;
const DEFAULT_MIN_MULTISIG_MEMBERS = 1;
const DEFAULT_MAX_MULTISIG_MEMBERS = 100;
const DEFAULT_PENDING_TRANSACTION_SETTLEMENT_DELAY = 10000;
const DEFAULT_PENDING_TRANSACTION_EXPIRY = 86400000; // 24 hours
const DEFAULT_PENDING_TRANSACTION_EXPIRY_CHECK_INTERVAL = 3600000; // 1 hour
const DEFAULT_MAX_SPENDABLE_DIGITS = 25;
const DEFAULT_MAX_TRANSACTION_MESSAGE_LENGTH = 256;
const DEFAULT_MAX_VOTES_PER_ACCOUNT = 5;
const DEFAULT_MAX_TRANSACTION_BACKPRESSURE_PER_ACCOUNT = 32;
const DEFAULT_MAX_PENDING_TRANSACTIONS_PER_ACCOUNT = 64;
const DEFAULT_MAX_CONSECUTIVE_BLOCK_FETCH_FAILURES = 5;
const DEFAULT_MAX_CONSECUTIVE_TRANSACTION_FETCH_FAILURES = 3;
const DEFAULT_CATCH_UP_CONSENSUS_POLL_COUNT = 6;
const DEFAULT_CATCH_UP_CONSENSUS_MIN_RATIO = .5;
const DEFAULT_GENESES = {
  0: 9
};
const DEFAULT_BLOCK_FORGER_SAMPLING_FACTOR = 4;
const DEFAULT_API_LIMIT = 100;
const DEFAULT_MAX_PUBLIC_API_LIMIT = 100;
const DEFAULT_MAX_PRIVATE_API_LIMIT = 10000;
const DEFAULT_MAX_PUBLIC_API_OFFSET = 1000;
const DEFAULT_MAX_PRIVATE_API_OFFSET = 10000;
const DEFAULT_KEY_INDEX_DIR_PATH = null;
const DEFAULT_KEY_INDEX_FILE_EXTENSION = '';
const DEFAULT_KEY_INDEX_FILE_LOCK_OPTIONS = {};

const PROPAGATION_MODE_DELAYED = 'delayed';
const PROPAGATION_MODE_IMMEDIATE = 'immediate';
const PROPAGATION_MODE_NONE = 'none';

const GENESIS_INDICATOR = 'gen';

// Forgers can shift their keys when they forge a block.
// Because there are 64 OTS keys in each Merkle signature tree, having more than
// 64 forgers will not guarantee that every forger will have an opportunity
// to shift their keys when their turn to forge arrives.
const MAX_FORGER_COUNT = 64;

const DEFAULT_MIN_TRANSACTION_FEES = {
  transfer: '10000000',
  vote: '20000000',
  unvote: '20000000',
  registerSigDetails: '500000000',
  registerMultisigDetails: '500000000',
  registerForgingDetails: '100000000',
  registerMultisigWallet: '50000000'
};

const DEFAULT_MIN_MULTISIG_REGISTRATION_FEE_PER_MEMBER = '100000000';
const DEFAULT_MIN_MULTISIG_TRANSACTION_FEE_PER_MEMBER = '500000';

const NO_PEER_LIMIT = -1;
const ACCOUNT_TYPE_SIG = 'sig';
const ACCOUNT_TYPE_MULTISIG = 'multisig';

module.exports = class LDPoSChainModule {
  constructor(options) {
    this.alias = options.alias || DEFAULT_MODULE_ALIAS;
    this.logger = options.logger || console;
    let { config } = options;
    let components = config.components || {};
    this.dalConfig = components.dal || {};

    if (!this.dalConfig) {
      throw new Error(
        `The ${this.alias} module config needs to have a components.dal property`
      );
    }
    if (!this.dalConfig.libPath) {
      throw new Error(
        `The ${this.alias} module config needs to have a components.dal.libPath property`
      );
    }
    const DAL = require(path.resolve(this.dalConfig.libPath));
    this.dal = new DAL({
      ...this.dalConfig,
      logger: this.logger
    });

    this.pendingTransactionStreams = {};
    this.pendingTransactionMap = new Map();
    this.pendingSignerMultisigTransactions = {};
    this.pendingBlocks = [];
    this.topActiveDelegates = [];
    this.topActiveDelegateAddressSet = new Set();
    this.lastProcessedBlock = null;
    this.lastHandledBlock = null;
    this.lastReceivedBlock = this.lastProcessedBlock;
    this.lastReceivedSignerAddressSet = new Set();
    this.ldposForgingClients = {};
    this.supplantedAddressSigPublicKeySet = new Set();
    this.supplantedAddressMultisigPublicKeySet = new Set();

    this.verifiedBlockInfoStream = new WritableConsumableStream();

    this.isCatchingUp = false;
    this.isActive = false;
    this.moduleState = {
      isOnTip: false
    };
  }

  get dependencies() {
    return ['app', 'network'];
  }

  get info() {
    return {
      author: 'Jonathan Gros-Dubois',
      version: pkg.version,
      name: DEFAULT_MODULE_ALIAS
    };
  }

  get events() {
    return [
      'bootstrap',
      'chainChanges',
      'transaction'
    ];
  }

  get actions() {
    return {
      getNetworkSymbol: {
        handler: async action => {
          return this.networkSymbol;
        },
        isPublic: true
      },
      getAccount: {
        handler: async action => {
          validateWalletAddress('walletAddress', action.params, this.networkSymbol);
          let { walletAddress } = action.params;
          return this.dal.getAccount(walletAddress);
        },
        isPublic: true
      },
      getAccountsByBalance: {
        handler: async action => {
          let maxOffset = action.isPublic ? this.maxPublicAPIOffset : this.maxPrivateAPIOffset;
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateOffset('offset', action.params, maxOffset);
          validateLimit('limit', action.params, maxLimit);
          validateSortOrder('order', action.params);
          let { offset, limit, order } = action.params;
          offset = this.sanitizeOffset(offset);
          limit = this.sanitizeLimit(limit);
          order = this.sanitizeOrder(order);
          return this.dal.getAccountsByBalance(offset, limit, order);
        },
        isPublic: true
      },
      getMultisigWalletMembers: {
        handler: async action => {
          validateWalletAddress('walletAddress', action.params, this.networkSymbol);
          let { walletAddress } = action.params;
          return this.dal.getMultisigWalletMembers(walletAddress);
        },
        isPublic: true
      },
      getMinMultisigRequiredSignatures: {
        handler: async action => {
          validateWalletAddress('walletAddress', action.params, this.networkSymbol);
          let { walletAddress } = action.params;
          let account = await this.getSanitizedAccount(walletAddress);
          if (account.type !== 'multisig') {
            let error = new Error(
              `Account ${walletAddress} was not a multisig wallet`
            );
            error.name = 'AccountWasNotMultisigError';
            error.type = 'InvalidActionError';
            throw error;
          }
          return account.requiredSignatureCount;
        },
        isPublic: true
      },
      getSignedPendingTransaction: {
        handler: async action => {
          validateTransactionId('transactionId', action.params);
          let { transactionId } = action.params;
          let transaction = this.pendingTransactionMap.get(transactionId);
          if (!transaction) {
            let error = new Error(
              `No pending transaction existed with ID ${transactionId}`
            );
            error.name = 'PendingTransactionDidNotExistError';
            error.type = 'InvalidActionError';
            throw error;
          }
          return transaction;
        },
        isPublic: true
      },
      getOutboundPendingTransactions: {
        handler: async action => {
          let maxOffset = action.isPublic ? this.maxPublicAPIOffset : this.maxPrivateAPIOffset;
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateWalletAddress('walletAddress', action.params, this.networkSymbol);
          validateOffset('offset', action.params, maxOffset);
          validateLimit('limit', action.params, maxLimit);
          let { walletAddress, offset, limit } = action.params;
          offset = this.sanitizeOffset(offset);
          limit = this.sanitizeLimit(limit);
          let senderTxnStream = this.pendingTransactionStreams[walletAddress];
          if (!senderTxnStream) {
            return [];
          }
          let transactionInfoList = [...senderTxnStream.transactionInfoMap.values()];
          return transactionInfoList
            .slice(offset, offset + limit)
            .map(txnInfo => this.simplifyTransaction(txnInfo.transaction, false));
        },
        isPublic: true
      },
      getPendingTransactionCount: {
        handler: async action => {
          return this.pendingTransactionMap.size;
        },
        isPublic: true
      },
      postTransaction: {
        handler: async action => {
          let { transaction } = action.params;
          return this.postTransaction(transaction);
        },
        isPublic: true
      },
      getTransaction: {
        handler: async action => {
          validateTransactionId('transactionId', action.params);
          let { transactionId } = action.params;
          return this.dal.getTransaction(transactionId);
        },
        isPublic: true
      },
      getTransactionsByTimestamp: {
        handler: async action => {
          let maxOffset = action.isPublic ? this.maxPublicAPIOffset : this.maxPrivateAPIOffset;
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateOffset('offset', action.params, maxOffset);
          validateLimit('limit', action.params, maxLimit);
          validateSortOrder('order', action.params);
          let { offset, limit, order } = action.params;
          offset = this.sanitizeOffset(offset);
          limit = this.sanitizeLimit(limit);
          order = this.sanitizeOrder(order);
          return this.dal.getTransactionsByTimestamp(offset, limit, order);
        },
        isPublic: true
      },
      getAccountTransactions: {
        handler: async action => {
          let maxOffset = action.isPublic ? this.maxPublicAPIOffset : this.maxPrivateAPIOffset;
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateWalletAddress('walletAddress', action.params, this.networkSymbol);
          if (action.params.fromTimestamp != null) {
            validateTimestamp('fromTimestamp', action.params);
          }
          validateOffset('offset', action.params, maxOffset);
          validateLimit('limit', action.params, maxLimit);
          validateSortOrder('order', action.params);
          let { walletAddress, fromTimestamp, offset, limit, order } = action.params;
          offset = this.sanitizeOffset(offset);
          limit = this.sanitizeLimit(limit);
          order = this.sanitizeOrder(order, 'asc');
          return this.dal.getAccountTransactions(walletAddress, fromTimestamp, offset, limit, order);
        },
        isPublic: true
      },
      getInboundTransactions: {
        handler: async action => {
          let maxOffset = action.isPublic ? this.maxPublicAPIOffset : this.maxPrivateAPIOffset;
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateWalletAddress('walletAddress', action.params, this.networkSymbol);
          if (action.params.fromTimestamp != null) {
            validateTimestamp('fromTimestamp', action.params);
          }
          validateOffset('offset', action.params, maxOffset);
          validateLimit('limit', action.params, maxLimit);
          validateSortOrder('order', action.params);
          let { walletAddress, fromTimestamp, offset, limit, order } = action.params;
          offset = this.sanitizeOffset(offset);
          limit = this.sanitizeLimit(limit);
          order = this.sanitizeOrder(order, 'asc');
          return this.dal.getInboundTransactions(walletAddress, fromTimestamp, offset, limit, order);
        },
        isPublic: true
      },
      getOutboundTransactions: {
        handler: async action => {
          let maxOffset = action.isPublic ? this.maxPublicAPIOffset : this.maxPrivateAPIOffset;
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateWalletAddress('walletAddress', action.params, this.networkSymbol);
          if (action.params.fromTimestamp != null) {
            validateTimestamp('fromTimestamp', action.params);
          }
          validateOffset('offset', action.params, maxOffset);
          validateLimit('limit', action.params, maxLimit);
          validateSortOrder('order', action.params);
          let { walletAddress, fromTimestamp, offset, limit, order } = action.params;
          offset = this.sanitizeOffset(offset);
          limit = this.sanitizeLimit(limit);
          order = this.sanitizeOrder(order, 'asc');
          return this.dal.getOutboundTransactions(walletAddress, fromTimestamp, offset, limit, order);
        },
        isPublic: true
      },
      getTransactionsFromBlock: {
        handler: async action => {
          let maxOffset = action.isPublic ? this.maxPublicAPIOffset : this.maxPrivateAPIOffset;
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateBlockId('blockId', action.params);
          validateOffset('offset', action.params, maxOffset);
          validateLimit('limit', action.params, maxLimit);
          let { blockId, offset, limit } = action.params;
          offset = this.sanitizeOffset(offset);
          limit = this.sanitizeLimit(limit);
          return this.dal.getTransactionsFromBlock(blockId, offset, limit);
        },
        isPublic: true
      },
      getInboundTransactionsFromBlock: {
        handler: async action => {
          validateWalletAddress('walletAddress', action.params, this.networkSymbol);
          validateBlockId('blockId', action.params);
          let { walletAddress, blockId } = action.params;
          return this.dal.getInboundTransactionsFromBlock(walletAddress, blockId);
        },
        isPublic: true
      },
      getOutboundTransactionsFromBlock: {
        handler: async action => {
          validateWalletAddress('walletAddress', action.params, this.networkSymbol);
          validateBlockId('blockId', action.params);
          let { walletAddress, blockId } = action.params;
          return this.dal.getOutboundTransactionsFromBlock(walletAddress, blockId);
        },
        isPublic: true
      },
      getLastBlockAtTimestamp: {
        handler: async action => {
          validateTimestamp('timestamp', action.params);
          let { timestamp } = action.params;
          return this.dal.getLastBlockAtTimestamp(timestamp);
        },
        isPublic: true
      },
      getMaxBlockHeight: {
        handler: async action => {
          return this.dal.getMaxBlockHeight();
        },
        isPublic: true
      },
      getBlocksFromHeight: {
        handler: async action => {
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateBlockHeight('height', action.params);
          validateLimit('limit', action.params, maxLimit);
          let { height, limit } = action.params;
          limit = this.sanitizeLimit(limit);
          return this.dal.getBlocksFromHeight(height, limit);
        },
        isPublic: true
      },
      getSignedBlock: {
        handler: async action => {
          validateBlockId('blockId', action.params);
          let { blockId } = action.params;
          return this.dal.getSignedBlock(blockId);
        },
        isPublic: true
      },
      getSignedBlocksFromHeight: {
        handler: async action => {
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateBlockHeight('height', action.params);
          validateLimit('limit', action.params, maxLimit);
          validateLimit('signatureLimit', action.params, Number.MAX_SAFE_INTEGER);
          let { height, limit, signatureLimit } = action.params;
          limit = this.sanitizeLimit(limit);
          let signedBlockList = await this.dal.getSignedBlocksFromHeight(height, limit);
          if (signatureLimit == null) {
            return signedBlockList;
          }
          return signedBlockList.map((signedBlock) => {
            return {
              ...signedBlock,
              signatures: signedBlock.signatures.slice(0, signatureLimit)
            };
          });
        },
        isPublic: true
      },
      getBlocksBetweenHeights: {
        handler: async action => {
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateBlockHeight('fromHeight', action.params);
          validateBlockHeight('toHeight', action.params);
          validateLimit('limit', action.params, maxLimit);
          let { fromHeight, toHeight, limit } = action.params;
          limit = this.sanitizeLimit(limit);
          return this.dal.getBlocksBetweenHeights(fromHeight, toHeight, limit);
        },
        isPublic: true
      },
      getBlockAtHeight: {
        handler: async action => {
          validateBlockHeight('height', action.params);
          let { height } = action.params;
          return this.dal.getBlockAtHeight(height);
        },
        isPublic: true
      },
      getBlock: {
        handler: async action => {
          validateBlockId('blockId', action.params);
          let { blockId } = action.params;
          return this.dal.getBlock(blockId);
        },
        isPublic: true
      },
      hasBlock: {
        handler: async action => {
          validateBlockId('blockId', action.params);
          let { blockId } = action.params;
          return this.dal.hasBlock(blockId);
        },
        isPublic: true
      },
      getBlocksByTimestamp: {
        handler: async action => {
          let maxOffset = action.isPublic ? this.maxPublicAPIOffset : this.maxPrivateAPIOffset;
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateOffset('offset', action.params, maxOffset);
          validateLimit('limit', action.params, maxLimit);
          validateSortOrder('order', action.params);
          let { offset, limit, order } = action.params;
          offset = this.sanitizeOffset(offset);
          limit = this.sanitizeLimit(limit);
          order = this.sanitizeOrder(order);
          return this.dal.getBlocksByTimestamp(offset, limit, order);
        },
        isPublic: true
      },
      getDelegate: {
        handler: async action => {
          validateWalletAddress('walletAddress', action.params, this.networkSymbol);
          let { walletAddress } = action.params;
          return this.dal.getDelegate(walletAddress);
        },
        isPublic: true
      },
      getDelegatesByVoteWeight: {
        handler: async action => {
          let maxOffset = action.isPublic ? this.maxPublicAPIOffset : this.maxPrivateAPIOffset;
          let maxLimit = action.isPublic ? this.maxPublicAPILimit : this.maxPrivateAPILimit;
          validateOffset('offset', action.params, maxOffset);
          validateLimit('limit', action.params, maxLimit);
          validateSortOrder('order', action.params);
          let { offset, limit, order } = action.params;
          offset = this.sanitizeOffset(offset);
          limit = this.sanitizeLimit(limit);
          order = this.sanitizeOrder(order);
          return this.dal.getDelegatesByVoteWeight(offset, limit, order);
        },
        isPublic: true
      },
      getForgingDelegates: {
        handler: async action => {
          return this.getForgingDelegates();
        },
        isPublic: true
      },
      getAccountVotes: {
        handler: async action => {
          validateWalletAddress('walletAddress', action.params, this.networkSymbol);
          let { walletAddress } = action.params;
          return this.dal.getAccountVotes(walletAddress);
        },
        isPublic: true
      },
      getMinFees: {
        handler: async action => {
          let minTransactionFees = {};
          let minTransactionFeeEntries = Object.entries(this.minTransactionFees || {});
          for (let [ txnType, fee ] of minTransactionFeeEntries) {
            minTransactionFees[txnType] = fee.toString();
          }
          return {
            minTransactionFees,
            minMultisigRegistrationFeePerMember: this.minMultisigRegistrationFeePerMember.toString(),
            minMultisigTransactionFeePerMember: this.minMultisigTransactionFeePerMember.toString()
          };
        },
        isPublic: true
      },
      getChainInfo: {
        handler: async action => this.chainInfo,
        isPublic: true
      },
      getAPIInfo: {
        handler: async action => this.apiInfo,
        isPublic: true
      },
      getModuleOptions: {
        handler: async action => this.options
      }
    };
  }

  simplifyBlock(signedBlock) {
    let { transactions, forgerSignature, signatures, ...simpleBlock } = signedBlock;
    return simpleBlock;
  }

  sanitizeOffset(offset) {
    if (offset == null) {
      return 0;
    }
    return offset;
  }

  sanitizeLimit(limit) {
    if (limit == null) {
      return this.apiLimit;
    }
    return limit;
  }

  sanitizeOrder(order, defaultOrder) {
    if (order == null) {
      return defaultOrder || 'desc';
    }
    return order;
  }

  async catchUpWithNetwork(options) {
    let {
      forgingInterval,
      fetchBlockEndConfirmations,
      fetchBlockLimit,
      fetchBlockPause,
      blockProcessingFailurePause,
      blockSignerMajorityCount,
      maxConsecutiveBlockFetchFailures
    } = options;

    let addedBlockCount = 0;
    let now = Date.now();
    if (
      Math.floor(this.lastHandledBlock.timestamp / forgingInterval) >= Math.floor(now / forgingInterval)
    ) {
      return {
        lastHeight: this.lastProcessedBlock.height,
        addedBlockCount
      };
    }

    this.logger.info('Attempting to catch up with the network');
    this.isCatchingUp = true;

    if (this.moduleState.isOnTip) {
      try {
        await this.updateModuleState({
          ...this.moduleState,
          isOnTip: false
        });
        this.moduleState.isOnTip = false;
      } catch (error) {
        this.logger.warn(error);
      }
    }

    let consecutiveFailureCount = 0;

    while (true) {
      if (!this.isActive) {
        break;
      }

      let nextBlockHeight = this.lastProcessedBlock.height + 1;
      this.logger.info(
        `Fetching new blocks from network starting at height ${nextBlockHeight}`
      );

      let newBlocks;
      let response;

      let matchingGenesesHeights = this.genesesHeights.filter(genHeight => genHeight <= nextBlockHeight);

      let genesesQueryParts = matchingGenesesHeights.map((genHeight) => {
        let genSignatureCount = this.geneses[genHeight];
        return `${GENESIS_INDICATOR}${genHeight}-${genSignatureCount}=1`;
      });

      let requiredSignatureCountAtStart = this.getRequiredBlockSignatureCountAtHeight(nextBlockHeight);
      let requiredSignatureCountAtEnd = this.getRequiredBlockSignatureCountAtHeight(nextBlockHeight + fetchBlockLimit);
      let signatureLimit = Math.max(requiredSignatureCountAtStart, requiredSignatureCountAtEnd);

      let actionRouteString = `${
        this.alias
      }?match=or&${
        genesesQueryParts.join('&')
      }`;

      try {
        response = await this.channel.invoke('network:request', {
          procedure: `${actionRouteString}:getSignedBlocksFromHeight`,
          data: {
            height: nextBlockHeight,
            limit: fetchBlockLimit,
            signatureLimit
          }
        });
        newBlocks = response.data;
        if (!Array.isArray(newBlocks)) {
          throw new Error('Response data from getSignedBlocksFromHeight action must be an array');
        }
        if (newBlocks.length > fetchBlockLimit) {
          throw new Error(
            `Peer getBlocksFromHeight action must not return more than ${
              fetchBlockLimit
            } blocks`
          );
        }
        consecutiveFailureCount = 0;
      } catch (error) {
        this.logger.warn(
          new Error(
            `Failed to invoke getSignedBlocksFromHeight action on network because of error: ${
              error.message
            }`
          )
        );
        if (++consecutiveFailureCount > maxConsecutiveBlockFetchFailures) {
          break;
        }
        await this.wait(fetchBlockPause);
        continue;
      }

      if (!newBlocks.length) {
        // If there are no new blocks, assume that we've finished synching.
        break;
      }

      let lastBlock = this.lastProcessedBlock;

      let allBlockIdsLineUp = true;
      for (let block of newBlocks) {
        if (block.previousBlockId !== lastBlock.id) {
          allBlockIdsLineUp = false;
          break;
        }
        lastBlock = block;
      }

      if (!allBlockIdsLineUp) {
        this.logger.warn(
          new Error(
            `Batch of blocks ending with the block ${
              lastBlock.id
            } was discarded because some of the block IDs did not line up`
          )
        );
        break;
      }

      let results = await Promise.all(
        [...Array(this.catchUpConsensusPollCount).keys()].map(async () => {
          try {
            let response = await this.channel.invoke('network:request', {
              procedure: `${this.alias}:hasBlock`,
              data: {
                blockId: lastBlock.id
              }
            });
            return response.data || false;
          } catch (error) {
            return false;
          }
        })
      );
      let matchingCount = results.reduce((total, peerHasBlock) => total + (peerHasBlock ? 1 : 0), 0);
      let consensusRatio = matchingCount / this.catchUpConsensusPollCount;

      if (consensusRatio < this.catchUpConsensusMinRatio) {
        this.logger.warn(
          new Error(
            `Batch of blocks ending with the block ${
              lastBlock.id
            } was discarded because the sampled network consensus of ${
              Math.round(consensusRatio * 10000) / 100
            }% did not meet the minimum required ratio`
          )
        );
        break;
      }

      let pause = fetchBlockPause;

      for (let block of newBlocks) {
        let blockHeight = this.lastProcessedBlock.height + 1;
        let requiredBlockSignatureCount = Math.min(
          blockSignerMajorityCount,
          this.getRequiredBlockSignatureCountAtHeight(blockHeight)
        );
        try {
          validateBlockSchema(
            block,
            0,
            this.maxTransactionsPerBlock,
            requiredBlockSignatureCount,
            this.forgerCount,
            this.networkSymbol
          );

          let {
            senderAccountDetails,
          } = await this.verifyFullySignedBlock(block, this.lastProcessedBlock);

          let blockSignificant = await this.isBlockSignificant(block);
          if (!blockSignificant) {
            throw new Error(`Block ${block.id} was not significant; it should not be part of the chain`);
          }
          try {
            await this.processBlock(block, senderAccountDetails, true);
          } catch (error) {
            pause = blockProcessingFailurePause;
            throw error;
          }
          this.lastHandledBlock = this.lastProcessedBlock;
          addedBlockCount++;
        } catch (error) {
          this.logger.warn(
            `Failed to process block ${
              block.id
            } while catching up with the network because of error: ${
              error.message
            }`
          );
          break;
        }
      }

      await this.wait(pause);
    }

    this.isCatchingUp = false;
    this.logger.info('Stopped catching up with the network');
    return {
      lastHeight: this.lastProcessedBlock.height,
      addedBlockCount
    };
  }

  async receiveLastBlockInfo(timeout) {
    this.verifiedBlockInfoStream.kill();
    try {
      return await this.verifiedBlockInfoStream.once(timeout);
    } catch (error) {
      throw new Error(
        `Timed out while waiting to receive the latest block from the network`
      );
    }
  }

  getCurrentBlockTimeSlot(forgingInterval) {
    return Math.floor(Date.now() / forgingInterval) * forgingInterval;
  }

  getForgingDelegateAddressAtTimestamp(timestamp) {
    let activeDelegates = this.topActiveDelegates;
    let slotIndex = Math.floor(timestamp / this.forgingInterval);
    let targetIndex = slotIndex % activeDelegates.length;
    if (!activeDelegates.length) {
      throw new Error('Could not find any active delegates');
    }
    return activeDelegates[targetIndex].address;
  }

  sha256(message, encoding) {
    return crypto.createHash('sha256').update(message, 'utf8').digest(encoding || 'base64');
  }

  async forgeBlock(forgerAddress, height, timestamp, transactions) {
    let blockData = {
      height,
      timestamp,
      previousBlockId: this.lastProcessedBlock ? this.lastProcessedBlock.id : null,
      numberOfTransactions: transactions.length,
      transactions
    };
    return this.ldposForgingClients[forgerAddress].prepareBlock(blockData);
  }

  async getSanitizedAccount(walletAddress) {
    let account = await this.dal.getAccount(walletAddress);
    return {
      ...account,
      balance: BigInt(account.balance)
    };
  }

  async getSanitizedTransaction(transactionId) {
    let transaction = await this.dal.getTransaction(transactionId);
    return {
      ...transaction,
      amount: BigInt(transaction.amount),
      fee: BigInt(transaction.fee)
    };
  }

  simplifyTransaction(transaction, withSignatureHashes) {
    let { senderSignature, signatures, ...txnWithoutSignatures} = transaction;
    if (!withSignatureHashes) {
      return txnWithoutSignatures;
    }
    if (signatures) {
      // If multisig transaction
      return {
        ...txnWithoutSignatures,
        signatures: signatures.map(signaturePacket => {
          let { signature, ...signaturePacketWithoutSignature } = signaturePacket;
          return {
            ...signaturePacketWithoutSignature,
            signatureHash: this.sha256(signature)
          };
        })
      };
    }
    // If regular sig transaction
    return {
      ...txnWithoutSignatures,
      senderSignatureHash: this.sha256(senderSignature)
    };
  }

  async getForgingDelegates() {
    return this.topActiveDelegates;
  }

  async fetchTopActiveDelegates() {
    let delegateList = await this.dal.getDelegatesByVoteWeight(0, this.forgerCount, 'desc');
    this.topActiveDelegates = delegateList.filter(delegate => delegate.voteWeight !== '0');
    this.topActiveDelegateAddressSet = new Set(this.topActiveDelegates.map(delegate => delegate.address));
  }

  async processBlock(block, senderAccountDetails, synched) {
    this.logger.info(
      `Started processing ${synched ? 'synched' : 'received'} block ${block.id}`
    );
    let { transactions, height, signatures: blockSignatureList } = block;

    let senderAddressSet = new Set();
    let recipientAddressSet = new Set();
    let multisigMemberAddressSet = new Set();

    for (let txn of transactions) {
      senderAddressSet.add(txn.senderAddress);
      if (txn.recipientAddress) {
        recipientAddressSet.add(txn.recipientAddress);
      }
      // For multisig transaction, add all signer accounts.
      if (txn.signatures) {
        for (let signaturePacket of txn.signatures) {
          multisigMemberAddressSet.add(signaturePacket.signerAddress);
        }
      }
    }

    let affectedAddressSet = new Set([
      ...senderAddressSet,
      ...recipientAddressSet,
      ...multisigMemberAddressSet,
      block.forgerAddress
    ]);
    let affectedAddressList = [...affectedAddressSet];

    let affectedAccountList = await Promise.all(
      affectedAddressList.map(async (address) => {
        if (senderAccountDetails[address]) {
          return senderAccountDetails[address].senderAccount;
        }
        let account;
        try {
          account = await this.getSanitizedAccount(address);
        } catch (error) {
          if (error.name === 'AccountDidNotExistError') {
            return {
              address,
              type: ACCOUNT_TYPE_SIG,
              balance: 0n
            };
          } else {
            throw new Error(
              `Failed to fetch account during block processing because of error: ${
                error.message
              }`
            );
          }
        }
        return account;
      })
    );

    let affectedAccountDetails = {};
    for (let account of affectedAccountList) {
      affectedAccountDetails[account.address] = {
        account,
        changes: {
          balance: account.balance
        },
        balanceDelta: 0n
      };
    }

    let forgerAccountChanges = affectedAccountDetails[block.forgerAddress].changes;
    forgerAccountChanges.forgingPublicKey = block.forgingPublicKey;
    forgerAccountChanges.nextForgingPublicKey = block.nextForgingPublicKey;
    forgerAccountChanges.nextForgingKeyIndex = block.nextForgingKeyIndex;

    let voteChangeList = [];
    let delegateRegistrationList = [];
    let multisigRegistrationList = [];
    let totalBlockFees = 0n;

    for (let txn of transactions) {
      let {
        type,
        senderAddress,
        fee,
        timestamp,
        signatures,
        sigPublicKey,
        nextSigPublicKey,
        nextSigKeyIndex
      } = txn;
      let senderAccountChanges = affectedAccountDetails[senderAddress].changes;

      let txnFee = BigInt(fee);
      totalBlockFees += txnFee;

      if (signatures) {
        for (let signaturePacket of signatures) {
          let memberAccountChanges = affectedAccountDetails[signaturePacket.signerAddress].changes;
          memberAccountChanges.multisigPublicKey = signaturePacket.multisigPublicKey;
          memberAccountChanges.nextMultisigPublicKey = signaturePacket.nextMultisigPublicKey;
          memberAccountChanges.nextMultisigKeyIndex = signaturePacket.nextMultisigKeyIndex;
        }
      } else {
        // If regular transaction (not multisig), update the account sig public keys.
        senderAccountChanges.sigPublicKey = sigPublicKey;
        senderAccountChanges.nextSigPublicKey = nextSigPublicKey;
        senderAccountChanges.nextSigKeyIndex = nextSigKeyIndex;
      }

      if (type === 'transfer') {
        let { recipientAddress, amount } = txn;
        let txnAmount = BigInt(amount);

        let recipientAccountChanges = affectedAccountDetails[recipientAddress].changes;
        senderAccountChanges.balance -= txnAmount + txnFee;
        senderAccountChanges.lastTransactionTimestamp = timestamp;
        recipientAccountChanges.balance += txnAmount;
      } else {
        senderAccountChanges.balance -= txnFee;
        senderAccountChanges.lastTransactionTimestamp = timestamp;
        if (type === 'vote' || type === 'unvote') {
          voteChangeList.push({
            id: txn.id,
            type,
            voterAddress: senderAddress,
            delegateAddress: txn.delegateAddress,
            transaction: txn
          });
        } else if (type === 'registerSigDetails') {
          let {
            newSigPublicKey,
            newNextSigPublicKey,
            newNextSigKeyIndex
          } = txn;
          senderAccountChanges.sigPublicKey = newSigPublicKey;
          senderAccountChanges.nextSigPublicKey = newNextSigPublicKey;
          senderAccountChanges.nextSigKeyIndex = newNextSigKeyIndex;
        } else if (type === 'registerMultisigDetails') {
          let {
            newMultisigPublicKey,
            newNextMultisigPublicKey,
            newNextMultisigKeyIndex
          } = txn;
          senderAccountChanges.multisigPublicKey = newMultisigPublicKey;
          senderAccountChanges.nextMultisigPublicKey = newNextMultisigPublicKey;
          senderAccountChanges.nextMultisigKeyIndex = newNextMultisigKeyIndex;
        } else if (type === 'registerForgingDetails') {
          let {
            newForgingPublicKey,
            newNextForgingPublicKey,
            newNextForgingKeyIndex
          } = txn;
          senderAccountChanges.forgingPublicKey = newForgingPublicKey;
          senderAccountChanges.nextForgingPublicKey = newNextForgingPublicKey;
          senderAccountChanges.nextForgingKeyIndex = newNextForgingKeyIndex;
          delegateRegistrationList.push({
            delegateAddress: senderAddress
          });
        } else if (type === 'registerMultisigWallet') {
          multisigRegistrationList.push({
            multisigAddress: senderAddress,
            memberAddresses: txn.memberAddresses,
            requiredSignatureCount: txn.requiredSignatureCount,
            transaction: txn
          });
        }
      }
      this.logger.info(`Processed transaction ${txn.id}`);
    }

    forgerAccountChanges.balance += totalBlockFees;

    await Promise.all(
      affectedAddressList.map(async (affectedAddress) => {
        let accountInfo = affectedAccountDetails[affectedAddress];
        let { account } = accountInfo;
        let accountChanges = accountInfo.changes;
        accountInfo.balanceDelta = accountChanges.balance - account.balance;
        let accountUpdatePacket = {
          ...accountChanges,
          balance: accountChanges.balance.toString(),
          updateHeight: height
        };
        if (account.updateHeight == null) {
          await this.dal.upsertAccount({
            ...account,
            ...accountUpdatePacket
          });
        } else if (account.updateHeight < height) {
          await this.dal.upsertAccount({
            address: account.address,
            type: account.type,
            ...accountUpdatePacket
          });
        }
      })
    );

    await Promise.all(
      delegateRegistrationList.map(async (delegateRegistration) => {
        let { delegateAddress } = delegateRegistration;
        let hasDelegate = await this.dal.hasDelegate(delegateAddress);
        if (!hasDelegate) {
          await this.dal.upsertDelegate({
            address: delegateAddress,
            voteWeight: '0'
          });
        }
      })
    );

    let accountVotes = {};
    let delegateVoters = {};

    await Promise.all(
      affectedAddressList.map(async (voterAddress) => {
        let delegateAddressList = await this.dal.getAccountVotes(voterAddress);
        accountVotes[voterAddress] = new Set(delegateAddressList);
        for (let delegateAddress of delegateAddressList) {
          if (!delegateVoters[delegateAddress]) {
            delegateVoters[delegateAddress] = new Set();
          }
          delegateVoters[delegateAddress].add(voterAddress);
        }
      })
    );

    let affectedDelegateDetails = {};
    let voteChangeDelegateAddressList = [...new Set(voteChangeList.map(voteChange => voteChange.delegateAddress))];
    let affectedDelegateAddressSet = new Set([
      ...Object.keys(delegateVoters),
      ...voteChangeDelegateAddressList
    ]);
    let affectedDelegateAddressList = [...affectedDelegateAddressSet];

    await Promise.all(
      affectedDelegateAddressList.map(async (delegateAddress) => {
        let delegate;
        try {
          delegate = await this.dal.getDelegate(delegateAddress);
        } catch (error) {
          throw new Error(
            `Failed to fetch delegate during block processing because of error: ${
              error.message
            }`
          );
        }

        let voteWeightDelta = 0n;
        let currentDelegateVoters = delegateVoters[delegateAddress];
        if (currentDelegateVoters) {
          for (let voterAddress of currentDelegateVoters) {
            let accountInfo = affectedAccountDetails[voterAddress];
            voteWeightDelta += accountInfo.balanceDelta;
          }
        }
        affectedDelegateDetails[delegateAddress] = {
          delegate,
          voteWeightDelta
        };
      })
    );

    let voterVoteChanges = {};

    for (let voteChange of voteChangeList) {
      if (!voterVoteChanges[voteChange.voterAddress]) {
        voterVoteChanges[voteChange.voterAddress] = [];
      }
      voterVoteChanges[voteChange.voterAddress].push(voteChange);
    }

    await Promise.all(
      Object.keys(voterVoteChanges).map(async (voterAddress) => {
        let currentVoteChangeList = voterVoteChanges[voterAddress];
        for (let voteChange of currentVoteChangeList) {
          let voterInfo = affectedAccountDetails[voterAddress];
          let { changes: voterChanges } = voterInfo;
          let delegateInfo = affectedDelegateDetails[voteChange.delegateAddress];
          try {
            if (voteChange.type === 'vote') {
              await this.dal.vote({
                id: voteChange.id,
                voterAddress,
                delegateAddress: voteChange.delegateAddress
              });
              delegateInfo.voteWeightDelta += voterChanges.balance;
            } else if (voteChange.type === 'unvote') {
              await this.dal.unvote({
                id: voteChange.id,
                voterAddress,
                delegateAddress: voteChange.delegateAddress
              });
              delegateInfo.voteWeightDelta -= voterChanges.balance;
            }
          } catch (error) {
            if (error.type === 'InvalidActionError') {
              voteChange.transaction.error = error;
              this.logger.debug(error.message);
            } else {
              throw error;
            }
          }
        }
      })
    );

    await Promise.all(
      affectedDelegateAddressList.map(async (delegateAddress) => {
        let delegateInfo = affectedDelegateDetails[delegateAddress];
        let { delegate } = delegateInfo;
        let updatedVoteWeight = BigInt(delegate.voteWeight) + delegateInfo.voteWeightDelta;
        let delegateUpdatePacket = {
          voteWeight: updatedVoteWeight.toString(),
          updateHeight: height
        };
        if (delegate.updateHeight == null || delegate.updateHeight < height) {
          await this.dal.upsertDelegate({
            address: delegate.address,
            ...delegateUpdatePacket
          });
        }
      })
    );

    for (let multisigRegistration of multisigRegistrationList) {
      let { multisigAddress, memberAddresses, requiredSignatureCount } = multisigRegistration;
      try {
        await this.dal.registerMultisigWallet(multisigAddress, memberAddresses, requiredSignatureCount);
        let senderAccountChanges = affectedAccountDetails[multisigAddress].changes;
        senderAccountChanges.type = ACCOUNT_TYPE_MULTISIG;
        senderAccountChanges.requiredSignatureCount = requiredSignatureCount;
      } catch (error) {
        if (error.type === 'InvalidActionError') {
          multisigRegistration.transaction.error = error;
          this.logger.debug(error.message);
        } else {
          throw error;
        }
      }
    }

    let numberOfSignaturesToStore = this.getRequiredBlockSignatureCountAtHeight(height);
    let blockSignaturesToStore = shuffle(blockSignatureList).slice(0, numberOfSignaturesToStore);

    await this.dal.upsertBlock({
      ...block,
      signatures: blockSignaturesToStore
    }, synched);

    this.logger.debug(`Upserted block ${block.id} into data store at height ${height}`);

    // Remove transactions which have been processed as part of the current block from pending transaction maps.
    for (let txn of transactions) {
      this.untrackPendingTransaction(txn);
    }

    // Update in-memory accounts in transaction streams to ensure that they have the latest sig and multisig public keys.
    await Promise.all(
      Object.keys(this.pendingTransactionStreams).map(async (senderAddress) => {
        let accountStream = this.pendingTransactionStreams[senderAddress];
        let pendingSenderAccount;
        let pendingMultisigMemberAccounts;
        try {
          let senderInfo = await accountStream.senderInfoPromise;
          pendingSenderAccount = senderInfo.senderAccount;
          pendingMultisigMemberAccounts = senderInfo.multisigMemberAccounts || {};
        } catch (error) {
          this.logger.debug(
            `Failed to update public keys of account ${
              senderAddress
            } in pending queue because of error: ${
              error.message
            }`
          );
          return;
        }

        let pendingAccountList = [pendingSenderAccount, ...Object.values(pendingMultisigMemberAccounts)];
        for (let pendingAccount of pendingAccountList) {
          let accountInfo = affectedAccountDetails[pendingAccount.address];
          if (!accountInfo) {
            continue;
          }
          let accountChanges = accountInfo.changes;

          if (accountChanges.sigPublicKey) {
            pendingAccount.sigPublicKey = accountChanges.sigPublicKey;
          }
          if (accountChanges.nextSigPublicKey) {
            pendingAccount.nextSigPublicKey = accountChanges.nextSigPublicKey;
          }
          if (accountChanges.nextSigKeyIndex) {
            pendingAccount.nextSigKeyIndex = accountChanges.nextSigKeyIndex;
          }
          if (accountChanges.multisigPublicKey) {
            pendingAccount.multisigPublicKey = accountChanges.multisigPublicKey;
          }
          if (accountChanges.nextMultisigPublicKey) {
            pendingAccount.nextMultisigPublicKey = accountChanges.nextMultisigPublicKey;
          }
          if (accountChanges.nextMultisigKeyIndex) {
            pendingAccount.nextMultisigKeyIndex = accountChanges.nextMultisigKeyIndex;
          }
          if (accountChanges.forgingPublicKey) {
            pendingAccount.forgingPublicKey = accountChanges.forgingPublicKey;
          }
          if (accountChanges.nextForgingPublicKey) {
            pendingAccount.nextForgingPublicKey = accountChanges.nextForgingPublicKey;
          }
          if (accountChanges.nextForgingKeyIndex) {
            pendingAccount.nextForgingKeyIndex = accountChanges.nextForgingKeyIndex;
          }
        }
      })
    );

    await this.fetchTopActiveDelegates();

    this.publishToChannel(`${this.alias}:chainChanges`, {
      type: 'addBlock',
      block: this.simplifyBlock(block)
    });

    this.lastProcessedBlock = block;
    this.logger.info(`Finished processing block ${block.id} at height ${block.height}`);
  }

  getRequiredBlockSignatureCountAtHeight(height) {
    let matchingGenesesHeights = this.genesesHeights.filter(genHeight => genHeight <= height);
    let maxMatchingGenHeight = matchingGenesesHeights.reduce(
      (maxHeight, genHeight) => {
        if (maxHeight == null || genHeight > maxHeight) {
          return genHeight;
        }
        return maxHeight;
      },
      null
    );
    return this.geneses[maxMatchingGenHeight];
  }

  async isBlockSignificant(block) {
    let delegateAccount = await this.getSanitizedAccount(block.forgerAddress);
    if (delegateAccount.updateHeight === block.height) {
      // This can occur if a past block processing attempt failed part-way through.
      return true;
    }
    return (
      block.transactions.length >= this.minTransactionsPerBlock ||
      delegateAccount.nextForgingPublicKey == null ||
      block.forgingPublicKey !== delegateAccount.forgingPublicKey
    );
  }

  async verifyTransactionDoesNotAlreadyExist(transaction) {
    let { id } = transaction;
    let wasTransactionAlreadyProcessed;
    try {
      wasTransactionAlreadyProcessed = await this.dal.hasTransaction(id);
    } catch (error) {
      throw new Error(
        `Failed to check if transaction has already been processed because of error: ${
          error.message
        }`
      );
    }
    if (wasTransactionAlreadyProcessed) {
      throw new Error(
        `Transaction ${id} has already been processed`
      );
    }
  }

  getTransactionFeeInfo(transaction) {
    let { type, fee } = transaction;
    let txnFee = BigInt(fee);
    let minFee = this.minTransactionFees[type] || 0n;
    if (type === 'registerMultisigWallet') {
      let { memberAddresses } = transaction;
      minFee += BigInt(memberAddresses.length) * this.minMultisigRegistrationFeePerMember;
    }
    return { type, fee: txnFee, minFee };
  }

  verifySigTransactionOffersMinFee(transaction) {
    let { type, fee, minFee } = this.getTransactionFeeInfo(transaction);

    if (fee < minFee) {
      throw new Error(
        `Transaction fee ${
          fee
        } was below the minimum fee of ${
          minFee
        } for this ${
          type
        } transaction`
      );
    }
  }

  verifyMultisigTransactionOffersMinFee(transaction, multisigMemberAccounts) {
    let { type, fee, minFee } = this.getTransactionFeeInfo(transaction);

    let multisigMemberCount = Object.keys(multisigMemberAccounts || {}).length;
    minFee += BigInt(multisigMemberCount) * this.minMultisigTransactionFeePerMember;

    if (fee < minFee) {
      throw new Error(
        `Transaction fee ${
          fee
        } was below the minimum fee of ${
          minFee
        } for this ${
          type
        } multisig transaction with ${
          multisigMemberCount
        } wallet members`
      );
    }
  }

  verifySigTransactionAuthentication(senderAccount, transaction, processSignatures, rejectSupplantedPublicKey) {
    validateSigTransactionSchema(transaction, processSignatures);

    if (senderAccount.sigPublicKey) {
      if (
        transaction.sigPublicKey !== senderAccount.sigPublicKey &&
        transaction.sigPublicKey !== senderAccount.nextSigPublicKey
      ) {
        throw new Error(
          `Transaction sigPublicKey did not match the sigPublicKey or nextSigPublicKey of the sender account ${
            senderAccount.address
          }`
        );
      }
    } else {
      // If the account does not yet have a sigPublicKey, check that the account
      // address corresponds to the sigPublicKey from the transaction.
      // The first 20 bytes (40 hex chars) of the public key have to match the sender address.
      let txnSigPublicKeyHex = transaction.sigPublicKey.slice(0, 40);
      let addressHex = senderAccount.address.slice(this.networkSymbol.length);
      if (txnSigPublicKeyHex !== addressHex) {
        throw new Error(
          `Transaction sigPublicKey did not correspond to the address of the sender account ${
            senderAccount.address
          }`
        );
      }
    }

    if (rejectSupplantedPublicKey && this.supplantedAddressSigPublicKeySet.has(`${senderAccount.address},${transaction.sigPublicKey}`)) {
      throw new Error(
        `Transaction sigPublicKey of the sender account ${
          senderAccount.address
        } has been supplanted`
      );
    }

    if (processSignatures) {
      // Check that the transaction signature corresponds to the public key.
      if (!this.ldposClient.verifyTransaction(transaction)) {
        throw new Error('Transaction senderSignature was invalid');
      }
    } else {
      if (!this.ldposClient.verifyTransactionId(transaction)) {
        throw new Error(
          `Transaction id ${transaction.id} was invalid`
        );
      }
    }
  }

  verifyMultisigTransactionAuthentication(senderAccount, multisigMemberAccounts, transaction, processSignatures, rejectSupplantedPublicKey) {
    validateMultisigTransactionSchema(
      transaction,
      senderAccount.requiredSignatureCount,
      this.maxMultisigMembers,
      this.networkSymbol,
      processSignatures
    );

    if (processSignatures) {
      let invalidPublicKeyMembers = [];
      let invalidSignatureMembers = [];
      let validSignaturePackets = [];
      for (let signaturePacket of transaction.signatures) {
        let {
          signerAddress,
          multisigPublicKey,
          nextMultisigKeyIndex
        } = signaturePacket;

        if (!multisigMemberAccounts[signerAddress]) {
          throw new Error(
            `Signer with address ${
              signerAddress
            } was not a member of multisig wallet ${
              senderAccount.address
            }`
          );
        }
        let memberAccount = multisigMemberAccounts[signerAddress];
        if (!memberAccount.multisigPublicKey) {
          throw new Error(
            `Multisig member account ${
              memberAccount.address
            } was not registered for multisig so they cannot sign multisig transactions`
          );
        }
        let isPublicKeyValid;
        if (rejectSupplantedPublicKey) {
          isPublicKeyValid = (
            (
              multisigPublicKey === memberAccount.multisigPublicKey ||
              multisigPublicKey === memberAccount.nextMultisigPublicKey
            ) &&
            !this.supplantedAddressMultisigPublicKeySet.has(`${memberAccount.address},${multisigPublicKey}`)
          );
        } else {
          isPublicKeyValid = (
            multisigPublicKey === memberAccount.multisigPublicKey ||
            multisigPublicKey === memberAccount.nextMultisigPublicKey
          );
        }
        if (!isPublicKeyValid) {
          invalidPublicKeyMembers.push(memberAccount.address);
          this.logger.debug(
            `The multisigPublicKey ${
              multisigPublicKey
            } of member ${
              memberAccount.address
            } in multisig transaction ${
              transaction.id
            } was invalid`
          );
        } else if (!this.ldposClient.verifyMultisigTransactionSignature(transaction, signaturePacket)) {
          invalidSignatureMembers.push(memberAccount.address);
        } else {
          validSignaturePackets.push(signaturePacket);
        }
      }
      if (invalidSignatureMembers.length) {
        throw new Error(
          `Multisig transaction contained invalid signatures from members: ${
            invalidSignatureMembers.join(', ')
          }`
        );
      }
      if (validSignaturePackets.length < senderAccount.requiredSignatureCount) {
        // This will only throw if there are not enough valid signatures on the transaction.
        // Some invalid member public keys may be tolerated because, due to the stateful nature
        // of the signature scheme, multisig public keys of members could change while a
        // multisig transaction which they signed is awaiting processing.
        // One member should not be able to prevent an otherwise valid multisig transaction from
        // being processed by changing their multisig public key.
        throw new Error(
          `Multisig transaction did not have enough valid signatures - Members with invalid public keys: ${
            invalidPublicKeyMembers.join(', ')
          }`
        );
      }
      // Sanitize the signatures array to exclude signatures of members which have invalid multisig public keys.
      transaction.signatures = validSignaturePackets;
    } else {
      if (!this.ldposClient.verifyTransactionId(transaction)) {
        throw new Error(
          `Multisig transaction id ${transaction.id} was invalid`
        );
      }
    }
  }

  verifyAccountMeetsRequirements(senderAccount, transaction) {
    let { senderAddress, amount, fee } = transaction;

    let txnTotal = BigInt(amount || 0) + BigInt(fee || 0);
    if (txnTotal > senderAccount.balance) {
      throw new Error(
        `Transaction amount plus fee was greater than the balance of sender ${
          senderAddress
        }`
      );
    }

    return txnTotal;
  }

  async verifySigTransactionAuthorization(senderAccount, transaction, fullCheck) {
    if (fullCheck) {
      this.verifySigTransactionOffersMinFee(transaction);
      await this.verifyTransactionDoesNotAlreadyExist(transaction);
    }
    return this.verifyAccountMeetsRequirements(senderAccount, transaction);
  }

  async verifySigTransactionAuth(senderAccount, transaction, signatureCheck, rejectSupplantedPublicKey) {
    this.verifySigTransactionAuthentication(senderAccount, transaction, signatureCheck, rejectSupplantedPublicKey);
    return this.verifySigTransactionAuthorization(senderAccount, transaction, signatureCheck);
  }

  async verifyMultisigTransactionAuthorization(senderAccount, multisigMemberAccounts, transaction, fullCheck) {
    if (fullCheck) {
      this.verifyMultisigTransactionOffersMinFee(transaction, multisigMemberAccounts);
      await this.verifyTransactionDoesNotAlreadyExist(transaction);
    }
    return this.verifyAccountMeetsRequirements(senderAccount, transaction);
  }

  async verifyMultisigTransactionAuth(senderAccount, multisigMemberAccounts, transaction, processSignatures, rejectSupplantedPublicKey) {
    this.verifyMultisigTransactionAuthentication(senderAccount, multisigMemberAccounts, transaction, processSignatures, rejectSupplantedPublicKey);
    return this.verifyMultisigTransactionAuthorization(senderAccount, multisigMemberAccounts, transaction, processSignatures);
  }

  async verifyFullySignedBlock(block, lastBlock) {
    let blockInfo = await this.verifyForgedBlock(block, lastBlock);

    await Promise.all(
      block.signatures.map(blockSignature => this.verifyBlockSignature(block, blockSignature))
    );

    return blockInfo;
  }

  async verifyForgedBlock(block, lastBlock) {
    if (block.id === lastBlock.id) {
      throw new Error(`Block ${block.id} has already been received`);
    }
    let expectedBlockHeight = lastBlock.height + 1;
    if (block.height !== expectedBlockHeight) {
      throw new Error(
        `Block height was invalid - Was ${block.height} but expected ${expectedBlockHeight}`
      );
    }
    if (
      block.timestamp % this.forgingInterval !== 0 ||
      block.timestamp - lastBlock.timestamp < this.forgingInterval
    ) {
      throw new Error(
        `Block timestamp ${block.timestamp} was invalid`
      );
    }
    let targetDelegateAddress = this.getForgingDelegateAddressAtTimestamp(block.timestamp);
    if (block.forgerAddress !== targetDelegateAddress) {
      throw new Error(
        `The block forgerAddress ${
          block.forgerAddress
        } did not match the expected forger delegate address ${
          targetDelegateAddress
        }`
      );
    }
    let targetDelegateAccount;
    try {
      targetDelegateAccount = await this.getSanitizedAccount(targetDelegateAddress);
    } catch (error) {
      throw new Error(
        `Failed to fetch delegate account ${
          targetDelegateAddress
        } because of error: ${
          error.message
        }`
      );
    }
    if (
      block.forgingPublicKey !== targetDelegateAccount.forgingPublicKey &&
      block.forgingPublicKey !== targetDelegateAccount.nextForgingPublicKey
    ) {
      throw new Error(
        `Block forgingPublicKey did not match the forgingPublicKey or nextForgingPublicKey of delegate ${
          targetDelegateAccount.address
        }`
      );
    }
    if (block.previousBlockId !== lastBlock.id) {
      throw new Error(
        `Block previousBlockId ${
          block.previousBlockId
        } did not match the id of the previous block ${
          lastBlock.id
        }`
      );
    }
    if (!this.ldposClient.verifyBlock(block)) {
      throw new Error('Block ID or signature was invalid');
    }
    let senderAccountDetails = await this.verifyBlockTransactions(block);
    return {
      senderAccountDetails
    };
  }

  async verifyBlockTransactions(block) {
    for (let transaction of block.transactions) {
      validateTransactionSchema(
        transaction,
        this.maxSpendableDigits,
        this.networkSymbol,
        this.maxTransactionMessageLength,
        this.minMultisigMembers,
        this.maxMultisigMembers
      );
    }

    await Promise.all(
      block.transactions.map(async (transaction) => {
        let existingTransaction;
        try {
          existingTransaction = await this.getSanitizedTransaction(transaction.id);
        } catch (error) {
          if (error.type !== 'InvalidActionError') {
            throw new Error(
              `Failed to check if transaction ${
                transaction.id
              } already existed during block processing`
            );
          }
        }
        if (existingTransaction && existingTransaction.blockId !== block.id) {
          throw new Error(
            `Block contained transaction ${
              existingTransaction.id
            } which was already processed as part of an earlier block`
          );
        }
      })
    );

    let senderTxns = {};
    for (let transaction of block.transactions) {
      let { senderAddress } = transaction;
      if (!senderTxns[senderAddress]) {
        senderTxns[senderAddress] = [];
      }
      senderTxns[senderAddress].push(transaction);
    }

    let senderAddressList = Object.keys(senderTxns);

    let senderAccountDetailsList = await Promise.all(
      senderAddressList.map(async (senderAddress) => {
        let senderAccountInfo;
        let senderAccount;
        let multisigMemberAccounts;
        try {
          let result = await this.getTransactionSenderAccountDetails(senderAddress);
          senderAccount = result.senderAccount;
          multisigMemberAccounts = result.multisigMemberAccounts;
          senderAccountInfo = {
            senderAccount: {
              ...senderAccount
            },
            multisigMemberAccounts: {
              ...multisigMemberAccounts
            }
          };
        } catch (error) {
          throw new Error(
            `Failed to fetch sender account ${
              senderAddress
            } for transaction verification as part of block verification because of error: ${
              error.message
            }`
          );
        }
        let senderTxnList = senderTxns[senderAddress];
        for (let senderTxn of senderTxnList) {
          try {
            let txnTotal;
            if (multisigMemberAccounts) {
              txnTotal = await this.verifyMultisigTransactionAuth(senderAccount, multisigMemberAccounts, senderTxn, false, false);
            } else {
              txnTotal = await this.verifySigTransactionAuth(senderAccount, senderTxn, false, false);
            }

            // Subtract valid transaction total from the in-memory senderAccount balance since it
            // may affect the verification of the next transaction in the stream.
            senderAccount.balance -= txnTotal;
          } catch (error) {
            throw new Error(
              `Failed to validate transaction ${
                senderTxn.id
              } during block verification because of error: ${
                error.message
              }`
            );
          }
        }
        return senderAccountInfo;
      })
    );

    let senderAccountDetails = {};
    for (let { senderAccount, multisigMemberAccounts } of senderAccountDetailsList) {
      senderAccountDetails[senderAccount.address] = {
        senderAccount,
        multisigMemberAccounts
      };
    }
    return senderAccountDetails;
  }

  validateBlockExists(block) {
    if (!block) {
      throw new Error('Block was not specified');
    }
  }

  validateSignatureCorrespondsToBlock(block, blockSignature) {
    if (blockSignature.blockId !== block.id) {
      throw new Error(
        `Block signature from signer ${
          blockSignature.signerAddress
        } was for a different block - Expected signature for block with ID ${
          block.id
        }`
      );
    }
  }

  validateSignatureBelongsToTopForger(blockSignature) {
    if (!this.topActiveDelegateAddressSet.has(blockSignature.signerAddress)) {
      throw new Error(
        `Account ${blockSignature.signerAddress} is not a top active delegate and therefore cannot be a block signer`
      );
    }
  }

  validateBlockSignerIsNotForger(block, blockSignature) {
    if (blockSignature.signerAddress === block.forgerAddress) {
      throw new Error(
        `Block forger ${block.forgerAddress} cannot re-sign their own block`
      );
    }
  }

  async verifyBlockSignaturePublicKeyBelongsToAccount(blockSignature) {
    let { signerAddress } = blockSignature;

    let signerAccount;
    try {
      signerAccount = await this.getSanitizedAccount(signerAddress);
    } catch (error) {
      throw new Error(
        `Failed to fetch signer account ${signerAddress} because of error: ${error.message}`
      );
    }

    if (
      blockSignature.forgingPublicKey !== signerAccount.forgingPublicKey &&
      blockSignature.forgingPublicKey !== signerAccount.nextForgingPublicKey
    ) {
      throw new Error(
        `Block signature forgingPublicKey did not match the forgingPublicKey or nextForgingPublicKey of the signer account ${
          signerAddress
        }`
      );
    }
  }

  verifyBlockSignatureIsAuthentic(block, blockSignature) {
    if (!this.ldposClient.verifyBlockSignature(block, blockSignature)) {
      throw new Error(
        `Signature of block signer ${
          blockSignature.signerAddress
        } for block ${
          block.id
        } was not authentic`
      );
    }
  }

  async verifyBlockSignature(block, blockSignature) {
    this.validateBlockExists(block);
    this.validateSignatureCorrespondsToBlock(block, blockSignature);
    this.validateSignatureBelongsToTopForger(blockSignature);
    this.validateBlockSignerIsNotForger(block, blockSignature);

    await this.verifyBlockSignaturePublicKeyBelongsToAccount(blockSignature);
    this.verifyBlockSignatureIsAuthentic(block, blockSignature);
  }

  async broadcastBlock(block) {
    try {
      await this.channel.invoke('network:emit', {
        event: `${this.alias}:block`,
        data: block,
        peerLimit: NO_PEER_LIMIT
      });
    } catch (error) {
      throw new Error(
        `Failed to emit block to the network because of error: ${error.message}`
      );
    }
    this.logger.info(`Broadcasted block ${block.id} to the network`);
  }

  async broadcastBlockSignature(signature) {
    try {
      await this.channel.invoke('network:emit', {
        event: `${this.alias}:blockSignature`,
        data: signature,
        peerLimit: NO_PEER_LIMIT
      });
    } catch (error) {
      throw new Error(
        `Failed to emit block signature to the network because of error: ${error.message}`
      );
    }
    this.logger.info(
      `Broadcasted block signature from signer ${signature.signerAddress} to the network`
    );
  }

  async signBlock(forgerAddress, block) {
    return this.ldposForgingClients[forgerAddress].signBlock(block);
  }

  async waitUntilNextBlockTimeSlot(options) {
    let { forgingInterval, timePollInterval } = options;
    let lastSlotIndex = Math.floor(Date.now() / forgingInterval);
    while (true) {
      if (!this.isActive) {
        break;
      }
      await this.wait(timePollInterval);
      let currentSlotIndex = Math.floor(Date.now() / forgingInterval);
      if (currentSlotIndex > lastSlotIndex) {
        break;
      }
    }
  }

  getSortedPendingTransactions(transactions, senderAccountDetails) {
    // This sorting algorithm groups transactions based on the sender address and
    // sorts based on the average fee. This is necessary because the signature algorithm is
    // stateful so the algorithm should give priority to older transactions which
    // may have been signed using an older public key.
    let transactionGroupMap = {};
    for (let txn of transactions) {
      if (!transactionGroupMap[txn.senderAddress]) {
        transactionGroupMap[txn.senderAddress] = {
          senderAddress: txn.senderAddress,
          transactions: [],
          totalFees: 0
        };
      }
      let transactionGroup = transactionGroupMap[txn.senderAddress];
      if (!transactionGroup.type) {
        transactionGroup.type = txn.sigPublicKey ? ACCOUNT_TYPE_SIG : ACCOUNT_TYPE_MULTISIG;
      }
      transactionGroup.totalFees += txn.fee;
      transactionGroup.transactions.push(txn);
    }
    let transactionGroupList = Object.values(transactionGroupMap);
    for (let transactionGroup of transactionGroupList) {
      if (transactionGroup.type === ACCOUNT_TYPE_SIG) {
        // For regular sig transactions, sort based on public key.
        // If public keys are the same, sort based on key index.
        let { senderAccount } = senderAccountDetails[transactionGroup.senderAddress];
        transactionGroup.transactions.sort((a, b) => {
          if (a.sigPublicKey === b.sigPublicKey) {
            if (a.nextSigKeyIndex < b.nextSigKeyIndex) {
              return -1;
            }
            if (a.nextSigKeyIndex > b.nextSigKeyIndex) {
              return 1;
            }
            return 0;
          }
          if (a.sigPublicKey === senderAccount.sigPublicKey) {
            return -1;
          }
          if (b.sigPublicKey === senderAccount.sigPublicKey) {
            return 1;
          }
          if (a.sigPublicKey === senderAccount.nextSigPublicKey) {
            return -1;
          }
          if (b.sigPublicKey === senderAccount.nextSigPublicKey) {
            return 1;
          }
          return 0;
        });
      } else {
        // For multisig transactions, sort based on the average priority value of public keys of signers.
        // If the priority is the same, sort based on the average key index delta of signers.
        let { multisigMemberAccounts } = senderAccountDetails[transactionGroup.senderAddress];
        let memberMinKeyIndexes = {};
        for (let txn of transactionGroup.transactions) {
          for (let signaturePacket of txn.signatures) {
            if (
              !memberMinKeyIndexes[signaturePacket.signerAddress] ||
              signaturePacket.nextMultisigKeyIndex < memberMinKeyIndexes[signaturePacket.signerAddress]
            ) {
              memberMinKeyIndexes[signaturePacket.signerAddress] = signaturePacket.nextMultisigKeyIndex;
            }
          }
        }
        transactionGroup.transactions.sort((a, b) => {
          let totalPublicKeyPriorityA = 0;
          let totalKeyIndexDeltaA = 0;
          for (let signaturePacket of a.signatures) {
            let signerAccount = multisigMemberAccounts[signaturePacket.signerAddress];
            let publicKeyPriority;
            if (signaturePacket.multisigPublicKey === signerAccount.multisigPublicKey) {
              publicKeyPriority = 0;
            } else if (signaturePacket.multisigPublicKey === signerAccount.nextMultisigPublicKey) {
              publicKeyPriority = 1;
            } else {
              publicKeyPriority = 2;
            }
            totalPublicKeyPriorityA += publicKeyPriority;
            let keyIndexDelta = signaturePacket.nextMultisigKeyIndex - memberMinKeyIndexes[signaturePacket.signerAddress];
            totalKeyIndexDeltaA += keyIndexDelta;
          }
          let averagePublicKeyPriorityA = totalPublicKeyPriorityA / a.signatures.length;
          let averageKeyIndexDeltaA = totalKeyIndexDeltaA / a.signatures.length;

          let totalPublicKeyPriorityB = 0;
          let totalKeyIndexDeltaB = 0;
          for (let signaturePacket of b.signatures) {
            let signerAccount = multisigMemberAccounts[signaturePacket.signerAddress];
            let publicKeyPriority;
            if (signaturePacket.multisigPublicKey === signerAccount.multisigPublicKey) {
              publicKeyPriority = 0;
            } else if (signaturePacket.multisigPublicKey === signerAccount.nextMultisigPublicKey) {
              publicKeyPriority = 1;
            } else {
              publicKeyPriority = 2;
            }
            totalPublicKeyPriorityB += publicKeyPriority;
            let keyIndexDelta = signaturePacket.nextMultisigKeyIndex - memberMinKeyIndexes[signaturePacket.signerAddress];
            totalKeyIndexDeltaB += keyIndexDelta;
          }
          let averagePublicKeyPriorityB = totalPublicKeyPriorityB / b.signatures.length;
          let averageKeyIndexDeltaB = totalKeyIndexDeltaB / b.signatures.length;

          if (averagePublicKeyPriorityA < averagePublicKeyPriorityB) {
            return -1;
          }
          if (averagePublicKeyPriorityA > averagePublicKeyPriorityB) {
            return 1;
          }
          if (averageKeyIndexDeltaA < averageKeyIndexDeltaB) {
            return -1;
          }
          if (averageKeyIndexDeltaA > averageKeyIndexDeltaB) {
            return 1;
          }
          return 0;
        });
      }
      transactionGroup.averageFee = transactionGroup.totalFees / transactionGroup.transactions.length;
    }

    transactionGroupList.sort((a, b) => {
      if (a.averageFee > b.averageFee) {
        return -1;
      }
      if (a.averageFee < b.averageFee) {
        return 1;
      }
      return 0;
    });

    let sortedTransactions = [];
    for (let transactionGroup of transactionGroupList) {
      for (let txn of transactionGroup.transactions) {
        sortedTransactions.push(txn);
      }
    }
    return sortedTransactions;
  }

  getForgingPassphrase(options) {
    if (!options) {
      throw new Error(
        `The forgingCredentials list of the ${
          this.alias
        } module config must contain objects`
      );
    }
    let {
      encryptedForgingPassphrase,
      forgingPassphrase
    } = options;

    if (encryptedForgingPassphrase == null && forgingPassphrase == null) {
      throw new Error(
        `Objects inside the forgingCredentials list of the ${
          this.alias
        } module config must have either a forgingPassphrase or encryptedForgingPassphrase property`
      );
    }

    if (encryptedForgingPassphrase) {
      if (!LDPOS_PASSWORD) {
        throw new Error(
          `Cannot decrypt an encryptedForgingPassphrase from the forgingCredentials list of the ${
            this.alias
          } of module config without a valid LDPOS_PASSWORD environment variable`
        );
      }
      if (forgingPassphrase) {
        throw new Error(
          `The forgingCredentials list of the ${
            this.alias
          } module config must contain objects with either a forgingPassphrase or encryptedForgingPassphrase but not both`
        );
      }
      try {
        let decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, CIPHER_KEY, CIPHER_IV);
        let decrypted = decipher.update(encryptedForgingPassphrase, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        forgingPassphrase = decrypted;
      } catch (error) {
        throw new Error(
          `Failed to decrypt encryptedForgingPassphrase from the forgingCredentials list of the ${
            this.alias
          } module config - Check that the LDPOS_PASSWORD environment variable is correct`
        );
      }
    }
    return forgingPassphrase;
  }

  async startBlockProcessingLoop() {
    let options = this.options;

    let {
      forgingInterval,
      forgingBlockBroadcastDelay,
      forgingSignatureBroadcastDelay,
      forgerCount,
      fetchBlockLimit,
      fetchBlockPause,
      blockProcessingFailurePause,
      fetchBlockEndConfirmations,
      propagationTimeout,
      pendingTransactionSettlementDelay,
      timePollInterval,
      maxTransactionsPerBlock,
      minMultisigMembers,
      maxMultisigMembers,
      minTransactionFees,
      maxConsecutiveBlockFetchFailures
    } = options;

    try {
      while (true) {
        let activeDelegateCount = Math.min(this.topActiveDelegates.length, forgerCount);
        let blockSignerMajorityCount = Math.floor(activeDelegateCount * this.minForgerBlockSignatureRatio);

        // If the node is already on the latest network height, it will just return it.
        let { lastHeight, addedBlockCount } = await this.catchUpWithNetwork({
          forgingInterval,
          fetchBlockLimit,
          fetchBlockPause,
          blockProcessingFailurePause,
          fetchBlockEndConfirmations,
          blockSignerMajorityCount,
          maxConsecutiveBlockFetchFailures
        });
        this.networkHeight = lastHeight;
        this.nodeHeight = this.networkHeight;

        if (!this.isActive) {
          this.resolveUnload && this.resolveUnload();
          break;
        }

        if (addedBlockCount) {
          if (this.autoSyncForgingKeyIndex) {
            await Promise.all(
              Object.keys(this.ldposForgingClients).map(async (forgerAddress) => {
                let forgingClient = this.ldposForgingClients[forgerAddress];
                let wasKeyIndexUpdated = await forgingClient.syncKeyIndex('forging');
                if (wasKeyIndexUpdated) {
                  this.logger.info(
                    `The forging key index of delegate ${
                      forgerAddress
                    } was shifted to ${
                      forgingClient.forgingKeyIndex
                    } after catching up with the network`
                  );
                }
              })
            );
          }
          activeDelegateCount = Math.min(this.topActiveDelegates.length, forgerCount);
          blockSignerMajorityCount = Math.floor(activeDelegateCount * this.minForgerBlockSignatureRatio);
        }

        let nextHeight = this.networkHeight + 1;

        await this.waitUntilNextBlockTimeSlot({
          forgingInterval,
          timePollInterval
        });

        if (!this.isActive) {
          this.resolveUnload && this.resolveUnload();
          break;
        }

        let blockTimestamp = this.getCurrentBlockTimeSlot(forgingInterval);
        let currentForgingDelegateAddress = this.getForgingDelegateAddressAtTimestamp(blockTimestamp);
        let block;

        this.supplantedAddressSigPublicKeySet.clear();
        this.supplantedAddressMultisigPublicKeySet.clear();

        let readyTransactions = [];
        let senderAddressList = Object.keys(this.pendingTransactionStreams);

        let senderAccountDetailsResultList = await Promise.all(
          senderAddressList.map(async (senderAddress) => {
            let senderAccountInfo;
            let senderAccount;
            let multisigMemberAccounts;
            try {
              let result = await this.getTransactionSenderAccountDetails(senderAddress);
              senderAccount = result.senderAccount;
              multisigMemberAccounts = result.multisigMemberAccounts;
              senderAccountInfo = {
                senderAccount: {
                  ...senderAccount
                },
                multisigMemberAccounts: {
                  ...multisigMemberAccounts
                }
              };
            } catch (err) {
              let error = new Error(
                `Failed to fetch sender account ${
                  senderAddress
                } for transaction verification because of error: ${
                  err.message
                }`
              );
              this.logger.error(error);
              return null;
            }

            let senderTxnStream = this.pendingTransactionStreams[senderAddress];
            if (!senderTxnStream) {
              return null;
            }
            let pendingTxnInfoMap = senderTxnStream.transactionInfoMap;

            for (let { transaction, receivedTimestamp } of pendingTxnInfoMap.values()) {
              try {
                let txnTotal;
                if (multisigMemberAccounts) {
                  txnTotal = await this.verifyMultisigTransactionAuth(senderAccount, multisigMemberAccounts, transaction, true, false);
                } else {
                  txnTotal = await this.verifySigTransactionAuth(senderAccount, transaction, true, false);
                }

                let isTransactionReady = true;

                if (blockTimestamp - receivedTimestamp >= pendingTransactionSettlementDelay) {
                  if (senderAccount.type === ACCOUNT_TYPE_MULTISIG) {
                    for (let signaturePacket of transaction.signatures) {
                      let signerAccount = multisigMemberAccounts[signaturePacket.signerAddress];
                      if (signaturePacket.multisigPublicKey === signerAccount.nextMultisigPublicKey) {
                        this.supplantedAddressMultisigPublicKeySet.add(`${signerAccount.address},${signerAccount.multisigPublicKey}`);
                      }
                    }
                  } else if (transaction.sigPublicKey === senderAccount.nextSigPublicKey) {
                    this.supplantedAddressSigPublicKeySet.add(`${senderAccount.address},${senderAccount.sigPublicKey}`);
                  }
                } else {
                  if (senderAccount.type === ACCOUNT_TYPE_MULTISIG) {
                    for (let signaturePacket of transaction.signatures) {
                      let signerAccount = multisigMemberAccounts[signaturePacket.signerAddress];
                      if (signaturePacket.multisigPublicKey === signerAccount.nextMultisigPublicKey) {
                        isTransactionReady = false;
                      }
                    }
                  } else if (transaction.sigPublicKey === senderAccount.nextSigPublicKey) {
                    isTransactionReady = false;
                  }
                }
                if (isTransactionReady) {
                  readyTransactions.push(transaction);
                  // Subtract valid transaction total from the in-memory senderAccount balance since it
                  // may affect the verification of the next transaction in the stream.
                  senderAccount.balance -= txnTotal;
                }
              } catch (error) {
                this.logger.debug(
                  `Removed pending transaction ${
                    transaction.id
                  } because of error: ${
                    error.message
                  }`
                );
                this.untrackPendingTransaction(transaction);
              }
            }
            return senderAccountInfo;
          })
        );

        let senderAccountDetailsList = senderAccountDetailsResultList.filter(senderDetails => senderDetails);
        let senderAccountDetails = {};
        for (let { senderAccount, multisigMemberAccounts } of senderAccountDetailsList) {
          senderAccountDetails[senderAccount.address] = {
            senderAccount,
            multisigMemberAccounts
          };
        }

        if (this.ldposForgingClients[currentForgingDelegateAddress]) {
          let pendingTransactions = this.getSortedPendingTransactions(readyTransactions, senderAccountDetails);
          let blockTransactions = pendingTransactions.slice(0, maxTransactionsPerBlock).map(txn => this.simplifyTransaction(txn, true));
          let [ forgedBlock, forgerAccount ] = await Promise.all([
            this.forgeBlock(currentForgingDelegateAddress, nextHeight, blockTimestamp, blockTransactions),
            this.dal.getAccount(currentForgingDelegateAddress)
          ]);
          block = forgedBlock;

          this.lastReceivedSignerAddressSet.clear();
          this.lastReceivedBlock = block;
          this.logger.debug(
            `Forged block ${block.id} at height ${block.height} as forger ${currentForgingDelegateAddress}`
          );

          await this.wait(forgingBlockBroadcastDelay);
          try {
            await this.broadcastBlock(block);
          } catch (error) {
            this.logger.error(error);
          }
        }

        try {
          if (!block) {
            // Will throw if block is not received in time.
            try {
              let blockInfo = await this.receiveLastBlockInfo(forgingBlockBroadcastDelay + propagationTimeout);
              block = blockInfo.block;
              senderAccountDetails = blockInfo.senderAccountDetails;
              this.logger.info(
                `Received valid block ${
                  block.id
                } from delegate ${
                  block.forgerAddress
                } with timestamp ${
                  block.timestamp
                } and height ${
                  block.height
                }`
              );
            } catch (error) {
              this.logger.debug(
                `No valid block was received from delegate ${
                  currentForgingDelegateAddress
                } with timestamp ${
                  blockTimestamp
                } and height ${
                  nextHeight
                }`
              );
              continue;
            }
          }

          let forgingAddressList = Object.keys(this.ldposForgingClients);

          await Promise.all([
            ...forgingAddressList.map(async (clientForgerAddress) => {
              if (
                this.topActiveDelegateAddressSet.has(clientForgerAddress) &&
                clientForgerAddress !== currentForgingDelegateAddress
              ) {
                try {
                  let [ selfSignature ] = await Promise.all([
                    this.signBlock(clientForgerAddress, block),
                    this.wait(forgingSignatureBroadcastDelay)
                  ]);
                  if (this.lastDoubleForgedBlockTimestamp === block.timestamp) {
                    throw new Error(
                      `Forging delegate ${
                        block.forgerAddress
                      } tried to double-forge`
                    );
                  }
                  try {
                    await this.verifyBlockSignature(block, selfSignature);
                  } catch (error) {
                    throw new Error(
                      `Delegate ${
                        clientForgerAddress
                      } failed to produce a valid block signature - ${
                        error.message
                      }`
                    );
                  }

                  this.logger.info(
                    `Delegate ${
                      clientForgerAddress
                    } produced a signature for block ${
                      block.id
                    }`
                  );

                  this.lastReceivedSignerAddressSet.add(selfSignature.signerAddress);
                  block.signatures.push(selfSignature);
                  await this.broadcastBlockSignature(selfSignature);
                } catch (error) {
                  this.logger.error(
                    new Error(
                      `Delegate ${
                        clientForgerAddress
                      } did not send its block signature for block ${
                        block.id
                      } because: ${
                        error.message
                      }`
                    )
                  );
                }
              }
            }),
            this.wait(forgingSignatureBroadcastDelay + propagationTimeout)
          ]);

          // Throw if the required number of valid signatures could not be gathered in time.
          if (block.signatures.length < blockSignerMajorityCount) {
            throw new Error(
              `Failed to receive enough block signatures before timeout - Received ${
                block.signatures.length
              } out of ${
                blockSignerMajorityCount
              } required signatures`
            );
          }

          this.logger.info(`Received a sufficient number of valid delegate signatures for block ${block.id}`);

          // Only process the block if it has transactions or if the forging delegate wants to change their forging key.
          let blockSignificant = await this.isBlockSignificant(block);
          if (blockSignificant) {
            await this.processBlock(block, senderAccountDetails, false);

            this.nodeHeight = nextHeight;
            this.networkHeight = nextHeight;
          } else {
            this.logger.debug(
              `Skipped processing block ${block.id} which contained less than the minimum amount of ${
                this.minTransactionsPerBlock
              } transactions`
            );
            this.publishToChannel(`${this.alias}:chainChanges`, {
              type: 'skipBlock',
              block: this.simplifyBlock(block)
            });
          }
          this.lastHandledBlock = block;
          if (!this.moduleState.isOnTip) {
            try {
              await this.updateModuleState({
                ...this.moduleState,
                isOnTip: true
              });
              this.moduleState.isOnTip = true;
            } catch (error) {
              this.logger.warn(error);
            }
          }
        } catch (error) {
          if (this.isActive) {
            this.logger.error(error);
          }
        }
      }
    } catch (error) {
      this.logger.error(error);
    }
  }

  async postTransaction(transaction) {
    try {
      await this.processReceivedTransaction(transaction, true, PROPAGATION_MODE_IMMEDIATE);
    } catch (error) {
      let err = new Error(error.message);
      err.name = 'InvalidTransactionError';
      err.type = 'InvalidActionError';
      throw err;
    }
  }

  async broadcastTransaction(transaction) {
    try {
      await this.channel.invoke('network:emit', {
        event: `${this.alias}:transaction`,
        data: transaction,
        peerLimit: NO_PEER_LIMIT
      });
    } catch (error) {
      throw new Error(
        `Failed to emit transaction to the network because of error: ${error.message}`
      );
    }
    this.logger.info(`Broadcasted transaction ${transaction.id} to the network`);
  }

  async propagateBlock(block, delayPropagation) {
    if (delayPropagation) {
      // This is a performance optimization to ensure that peers
      // will not receive multiple instances of the same block at the same time.
      let randomPropagationDelay = Math.round(Math.random() * this.propagationRandomness);
      await this.wait(randomPropagationDelay);
    }
    try {
      await this.broadcastBlock(block);
    } catch (error) {
      this.logger.error(error);
    }
  }

  async propagateTransaction(transaction, delayPropagation) {
    if (delayPropagation) {
      // This is a performance optimization to ensure that peers
      // will not receive multiple instances of the same transaction at the same time.
      let randomPropagationDelay = Math.round(Math.random() * this.propagationRandomness);
      await this.wait(randomPropagationDelay);
    }
    try {
      await this.broadcastTransaction(transaction);
    } catch (error) {
      this.logger.error(error);
    }
  }

  async getTransactionMultisigMemberAccounts(senderAddress) {
    let multisigMemberAddresses;
    try {
      multisigMemberAddresses = await this.dal.getMultisigWalletMembers(senderAddress);
    } catch (error) {
      throw new Error(
        `Failed to fetch member addresses for multisig wallet ${
          senderAddress
        } because of error: ${error.message}`
      );
    }
    let multisigMemberAccounts = {};
    try {
      let multisigMemberAccountList = await Promise.all(
        multisigMemberAddresses.map(memberAddress => this.getSanitizedAccount(memberAddress))
      );
      for (let memberAccount of multisigMemberAccountList) {
        multisigMemberAccounts[memberAccount.address] = memberAccount;
      }
    } catch (error) {
      throw new Error(
        `Failed to fetch member accounts for multisig wallet ${
          senderAddress
        } because of error: ${error.message}`
      );
    }
    return multisigMemberAccounts;
  }

  async getTransactionSenderAccountDetails(senderAddress) {
    let senderAccount;
    try {
      senderAccount = await this.getSanitizedAccount(senderAddress);
    } catch (error) {
      if (error.name === 'AccountDidNotExistError') {
        throw new Error(
          `Sender account ${senderAddress} did not exist`
        );
      }
      throw new Error(
        `Failed to fetch sender account ${senderAddress} because of error: ${error.message}`
      );
    }
    let multisigMemberAccounts;
    if (senderAccount.type === ACCOUNT_TYPE_MULTISIG) {
      multisigMemberAccounts = await this.getTransactionMultisigMemberAccounts(senderAddress);
    } else {
      multisigMemberAccounts = null;
    }
    return {
      senderAccount,
      multisigMemberAccounts
    };
  }

  isAccountStreamBusy(accountStream) {
    return !!(accountStream.pendingTransactionVerificationCount || accountStream.transactionInfoMap.size);
  }

  async processReceivedTransaction(transaction, rejectSupplantedPublicKey, propagationMode) {
    try {
      validateTransactionSchema(
        transaction,
        this.maxSpendableDigits,
        this.networkSymbol,
        this.maxTransactionMessageLength,
        this.minMultisigMembers,
        this.maxMultisigMembers
      );
    } catch (error) {
      throw new Error(`Received invalid transaction ${transaction.id} - ${error.message}`);
    }

    this.logger.info(
      `Received transaction ${transaction.id}`
    );

    let senderAccount;
    let multisigMemberAccounts;

    let { senderAddress } = transaction;

    let resolveTransaction;
    let rejectTransaction;
    let txnAuthorizedPromise = new Promise((resolve, reject) => {
      resolveTransaction = resolve;
      rejectTransaction = reject;
    });

    // This ensures that transactions sent from the same account are processed serially but
    // transactions sent from different accounts can be verified in parallel.

    if (this.pendingTransactionStreams[senderAddress]) {
      let accountStream = this.pendingTransactionStreams[senderAddress];

      if (accountStream.transactionInfoMap.size >= this.maxPendingTransactionsPerAccount) {
        throw new Error(
          `Transaction ${
            transaction.id
          } was rejected because account ${
            senderAddress
          } has exceeded the maximum allowed pending transaction count of ${
            this.maxPendingTransactionsPerAccount
          }`
        );
      }

      let backpressure = accountStream.getBackpressure();

      if (backpressure >= this.maxTransactionBackpressurePerAccount) {
        throw new Error(
          `Transaction ${
            transaction.id
          } was rejected because account ${
            senderAddress
          } has exceeded the maximum allowed pending transaction backpressure of ${
            this.maxTransactionBackpressurePerAccount
          }`
        );
      }

      accountStream.pendingTransactionVerificationCount++;

      try {
        let senderInfo = await accountStream.senderInfoPromise;
        senderAccount = senderInfo.senderAccount;
        multisigMemberAccounts = senderInfo.multisigMemberAccounts;

        if (multisigMemberAccounts) {
          this.verifyMultisigTransactionAuthentication(senderAccount, multisigMemberAccounts, transaction, true, rejectSupplantedPublicKey);
        } else {
          this.verifySigTransactionAuthentication(senderAccount, transaction, true, rejectSupplantedPublicKey);
        }
        accountStream.write({
          transaction,
          resolveTransaction,
          rejectTransaction
        });
      } catch (error) {
        accountStream.pendingTransactionVerificationCount--;
        this.cleanupPendingTransactionStream(senderAddress);
        throw new Error(
          `Received unauthorized transaction ${transaction.id} in queue - ${error.message}`
        );
      }

      await txnAuthorizedPromise;

      return { senderAccount, multisigMemberAccounts };
    }

    let accountStream = new WritableConsumableStream();
    accountStream.transactionInfoMap = new Map();
    accountStream.pendingTransactionVerificationCount = 1;
    let accountStreamConsumer = accountStream.createConsumer();
    accountStream.senderInfoPromise = this.getTransactionSenderAccountDetails(senderAddress);

    this.pendingTransactionStreams[senderAddress] = accountStream;

    try {
      let senderInfo = await accountStream.senderInfoPromise;
      senderAccount = senderInfo.senderAccount;
      multisigMemberAccounts = senderInfo.multisigMemberAccounts;

      if (multisigMemberAccounts) {
        this.verifyMultisigTransactionAuthentication(senderAccount, multisigMemberAccounts, transaction, true, rejectSupplantedPublicKey);
      } else {
        this.verifySigTransactionAuthentication(senderAccount, transaction, true, rejectSupplantedPublicKey);
      }
      accountStream.write({
        transaction,
        resolveTransaction,
        rejectTransaction
      });
    } catch (error) {
      accountStream.pendingTransactionVerificationCount--;
      this.cleanupPendingTransactionStream(senderAddress);
      throw new Error(`Received unauthorized transaction ${transaction.id} - ${error.message}`);
    }

    (async () => {
      for await (let txnInfo of accountStreamConsumer) {
        let {
          transaction: currentTxn,
          resolveTransaction: resolveTxn,
          rejectTransaction: rejectTxn
        } = txnInfo;

        let verificationError;

        try {
          let txnTotal;
          if (multisigMemberAccounts) {
            txnTotal = await this.verifyMultisigTransactionAuthorization(senderAccount, multisigMemberAccounts, currentTxn, true);
          } else {
            txnTotal = await this.verifySigTransactionAuthorization(senderAccount, currentTxn, true);
          }

          if (accountStream.transactionInfoMap.has(currentTxn.id)) {
            verificationError = new Error(`Transaction ${currentTxn.id} has already been received before`);
          } else {
            // Subtract valid transaction total from the in-memory senderAccount balance since it
            // may affect the verification of the next transaction in the stream.
            senderAccount.balance -= txnTotal;

            if (multisigMemberAccounts) {
              this.trackPendingMultisigTransactionSigners(currentTxn);
            } else {
              // Do not allow an account to change their multisig public key while there are pending multisig transactions in the queue
              // which depend on that account as a signer.
              if (
                currentTxn.type === 'registerMultisigDetails' &&
                this.pendingSignerMultisigTransactions[currentTxn.senderAddress]
              ) {
                throw new Error(
                  `Transaction ${
                    currentTxn.id
                  } of type registerMultisigDetails from the account ${
                    currentTxn.senderAddress
                  } could not be processed while there were pending multisig transactions with that account as a signer`
                );
              }

              // Do not allow an account to change their sig public key while there are pending sig transactions in the queue from that account.
              if (currentTxn.type === 'registerSigDetails' && accountStream.transactionInfoMap.size) {
                throw new Error(
                  `Transaction ${
                    currentTxn.id
                  } of type registerSigDetails from the account ${
                    currentTxn.senderAddress
                  } could not be processed while there were pending transactions from that account`
                );
              }
            }

            this.pendingTransactionMap.set(currentTxn.id, currentTxn);
            accountStream.transactionInfoMap.set(currentTxn.id, {
              transaction: currentTxn,
              receivedTimestamp: Date.now()
            });

            if (propagationMode !== PROPAGATION_MODE_NONE) {
              this.propagateTransaction(currentTxn, propagationMode === PROPAGATION_MODE_DELAYED);
            }
          }
        } catch (error) {
          verificationError = new Error(`Received invalid transaction - ${error.message}`);
        }
        if (verificationError) {
          rejectTxn(verificationError);
        } else {
          resolveTxn();
        }

        accountStream.pendingTransactionVerificationCount--;
        if (!this.isAccountStreamBusy(accountStream)) {
          delete this.pendingTransactionStreams[senderAddress];
          break;
        }
      }
    })();

    await txnAuthorizedPromise;

    return { senderAccount, multisigMemberAccounts };
  }

  async startTransactionPropagationLoop() {
    this.channel.subscribe(`network:event:${this.alias}:transaction`, (event) => {
      // Process transactions in parallel.
      (async () => {
        try {
          await this.processReceivedTransaction(event.data, true, PROPAGATION_MODE_DELAYED);
        } catch (error) {
          this.logger.debug(error.message);
        }
      })();
    });
  }

  async getSignedPendingTransaction(transactionId) {
    let response = await this.channel.invoke('network:request', {
      procedure: `${this.alias}:getSignedPendingTransaction`,
      data: {
        transactionId
      }
    });
    if (!response.data) {
      throw new Error(
        `Response to getSignedPendingTransaction action was missing a data property`
      );
    }
    return response.data;
  }

  async fetchSignedPendingTransaction(transactionId, maxAttempts) {
    for (let i = 0; i < maxAttempts; i++) {
      this.logger.info(
        `Attempting to fetch pending transaction ${transactionId} from the network - Attempt #${i + 1}`
      );
      try {
        let transaction = await this.getSignedPendingTransaction(transactionId);
        await this.processReceivedTransaction(transaction, false, PROPAGATION_MODE_NONE);
        return;
      } catch (error) {
        this.logger.debug(
          `Failed to fetch pending transaction ${transactionId} from the network because of error: ${error.message}`
        );
      }
    }
    throw new Error(
      `Failed to fetch pending transaction ${transactionId} from the network after ${maxAttempts} attempts`
    );
  }

  async startBlockPropagationLoop() {
    let channel = this.channel;
    channel.subscribe(`network:event:${this.alias}:block`, (event) => {
      // Process blocks in parallel.
      (async () => {
        let block = event.data;
        this.logger.info(`Received block ${block && block.id}`);

        if (this.isCatchingUp) {
          this.logger.debug(
            'Block was ignored because the node was catching up with the network'
          );
          return;
        }

        let senderAccountDetails;
        try {
          validateBlockSchema(block, 0, this.maxTransactionsPerBlock, 0, 0, this.networkSymbol);

          if (block.id === this.lastReceivedBlock.id) {
            this.logger.info(`Block ${block.id} has already been received before`);
            return;
          }

          let blockInfo = await this.verifyForgedBlock(block, this.lastProcessedBlock);
          senderAccountDetails = blockInfo.senderAccountDetails;
          let currentBlockTimeSlot = this.getCurrentBlockTimeSlot(this.forgingInterval);
          if (block.timestamp !== currentBlockTimeSlot) {
            throw new Error(
              `Block timestamp ${block.timestamp} did not correspond to the current time slot ${currentBlockTimeSlot}`
            );
          }
        } catch (error) {
          this.logger.debug(
            `Received invalid block ${block && block.id} - ${error.message}`
          );
          return;
        }

        // If double-forged block was received.
        if (block.timestamp === this.lastReceivedBlock.timestamp) {
          if (this.lastDoubleForgedBlockTimestamp !== this.lastReceivedBlock.timestamp) {
            this.lastDoubleForgedBlockTimestamp = this.lastReceivedBlock.timestamp;
            // The first time a double-forged block is received, propagate it to ensure that other nodes in the
            // network can verify for themselves that double-forging has taken place.
            await this.propagateBlock(block, true);
          }
          this.logger.debug(
            `Block ${block.id} was forged with the same timestamp as the last block ${this.lastReceivedBlock.id}`
          );
          return;
        }

        let { transactions } = block;
        let senderTransactions = {};
        for (let txn of transactions) {
          if (!senderTransactions[txn.senderAddress]) {
            senderTransactions[txn.senderAddress] = [];
          }
          senderTransactions[txn.senderAddress].push(txn);
        }

        try {
          await Promise.all(
            Object.values(senderTransactions).map(async (senderTxnList) => {
              await Promise.all(
                senderTxnList.map(async (txn) => {
                  let pendingTxnStream = this.pendingTransactionStreams[txn.senderAddress];
                  if (pendingTxnStream && pendingTxnStream.transactionInfoMap.has(txn.id)) {
                    return;
                  }
                  try {
                    await this.fetchSignedPendingTransaction(txn.id, this.maxConsecutiveTransactionFetchFailures);
                  } catch (error) {
                    throw new Error(
                      `Block ${block.id} contained an unrecognized transaction ${txn.id} - ${error.message}`
                    );
                  }
                })
              );
            })
          );
        } catch (error) {
          this.logger.debug(error.message);
          return;
        }

        for (let txn of transactions) {
          let pendingTxnStream = this.pendingTransactionStreams[txn.senderAddress];
          if (!pendingTxnStream || !pendingTxnStream.transactionInfoMap.has(txn.id)) {
            this.logger.debug(
              `Block ${block.id} contained an unrecognized transaction ${txn.id}`
            );
            return;
          }
          let pendingTxn = pendingTxnStream.transactionInfoMap.get(txn.id).transaction;

          if (txn.signatures) {
            // For multisig transaction.
            let pendingTxnSignatures = {};
            for (let pendingSignaturePacket of pendingTxn.signatures) {
              pendingTxnSignatures[pendingSignaturePacket.signerAddress] = pendingSignaturePacket;
            }
            let allSignaturesMatchPending = txn.signatures.every((signaturePacket) => {
              let expectedSignaturePacket = pendingTxnSignatures[signaturePacket.signerAddress];
              if (!expectedSignaturePacket) {
                return false;
              }
              let expectedSignatureHash = this.sha256(expectedSignaturePacket.signature);
              return signaturePacket.signatureHash === expectedSignatureHash;
            });

            if (!allSignaturesMatchPending) {
              this.logger.debug(
                `Block ${block.id} contained a multisig transaction ${txn.id} with invalid or unrecognized signature hashes`
              );
              return;
            }
          } else {
            // For sig transaction.
            let expectedSenderSignatureHash = this.sha256(pendingTxn.senderSignature);
            if (txn.senderSignatureHash !== expectedSenderSignatureHash) {
              this.logger.debug(
                `Block ${block.id} contained a sig transaction ${txn.id} with an invalid sender signature hash`
              );
              return;
            }
          }
        }

        this.lastReceivedSignerAddressSet.clear();
        this.lastReceivedBlock = block;
        this.verifiedBlockInfoStream.write({
          block: this.lastReceivedBlock,
          senderAccountDetails
        });

        await this.propagateBlock(block, true);
      })();
    });
  }

  async startBlockSignaturePropagationLoop() {
    let channel = this.channel;
    channel.subscribe(`network:event:${this.alias}:blockSignature`, (event) => {
      // Verify block signatures in parallel.
      (async () => {
        let blockSignature = event.data;

        this.logger.info(
          `Received block signature from signer ${blockSignature && blockSignature.signerAddress}`
        );

        if (this.isCatchingUp) {
          this.logger.debug(
            'Block signature was ignored because the node was catching up with the network'
          );
          return;
        }

        validateBlockSignatureSchema(blockSignature, this.networkSymbol);

        let lastReceivedBlock = this.lastReceivedBlock;

        try {
          this.validateBlockExists(lastReceivedBlock);
          this.validateSignatureCorrespondsToBlock(lastReceivedBlock, blockSignature);
          this.validateSignatureBelongsToTopForger(blockSignature);
          this.validateBlockSignerIsNotForger(lastReceivedBlock, blockSignature);

          if (this.lastReceivedSignerAddressSet.has(blockSignature.signerAddress)) {
            this.logger.info(
              `Block signature of delegate ${blockSignature.signerAddress} has already been received before`
            );
            return;
          }

          this.lastReceivedSignerAddressSet.add(blockSignature.signerAddress);

          await this.verifyBlockSignaturePublicKeyBelongsToAccount(blockSignature);
          this.verifyBlockSignatureIsAuthentic(lastReceivedBlock, blockSignature);
        } catch (error) {
          this.logger.debug(
            `Received invalid delegate block signature - ${error.message}`
          );
          return;
        }

        lastReceivedBlock.signatures.push(blockSignature);

        // This is a performance optimization to ensure that peers
        // will not receive multiple instances of the same signature at the same time.
        let randomPropagationDelay = Math.round(Math.random() * this.propagationRandomness);
        await this.wait(randomPropagationDelay);

        if (blockSignature.blockId !== this.lastReceivedBlock.id) {
          this.logger.debug(
            `Discarded block signature from signer ${
              blockSignature.signerAddress
            } because the block ${
              blockSignature.blockId
            } is no longer the latest active block`
          );
          return;
        }

        try {
          await this.broadcastBlockSignature(blockSignature);
        } catch (error) {
          this.logger.error(error);
        }
      })();
    });
  }

  trackPendingMultisigTransactionSigners(transaction) {
    if (transaction.signatures) {
      for (let signaturePacket of transaction.signatures) {
        let { signerAddress } = signaturePacket;
        if (!this.pendingSignerMultisigTransactions[signerAddress]) {
          this.pendingSignerMultisigTransactions[signerAddress] = new Set();
        }
        this.pendingSignerMultisigTransactions[signerAddress].add(transaction.id);
      }
    }
  }

  untrackPendingMultisigTransactionSigners(transaction) {
    if (transaction.signatures) {
      for (let signaturePacket of transaction.signatures) {
        let { signerAddress } = signaturePacket;
        let multisigTxnSet = this.pendingSignerMultisigTransactions[signerAddress];
        if (multisigTxnSet) {
          multisigTxnSet.delete(transaction.id);
          if (!multisigTxnSet.size) {
            delete this.pendingSignerMultisigTransactions[signerAddress];
          }
        }
      }
    }
  }

  cleanupPendingTransactionStream(senderAddress) {
    let transactionStream = this.pendingTransactionStreams[senderAddress];
    if (!this.isAccountStreamBusy(transactionStream)) {
      transactionStream.close();
      delete this.pendingTransactionStreams[senderAddress];
    }
  }

  untrackPendingTransaction(transaction) {
    let { senderAddress } = transaction;
    this.untrackPendingMultisigTransactionSigners(transaction);
    let senderTxnStream = this.pendingTransactionStreams[senderAddress];
    if (senderTxnStream) {
      this.pendingTransactionMap.delete(transaction.id);
      senderTxnStream.transactionInfoMap.delete(transaction.id);
      this.cleanupPendingTransactionStream(senderAddress);
    }
  }

  expirePendingTransactionStreams(expiry) {
    let now = Date.now();

    let pendingSenderList = Object.keys(this.pendingTransactionStreams);
    for (let senderAddress of pendingSenderList) {
      let senderTxnStream = this.pendingTransactionStreams[senderAddress];
      let pendingTxnInfoMap = senderTxnStream.transactionInfoMap;
      for (let { transaction, receivedTimestamp } of pendingTxnInfoMap.values()) {
        if (now - receivedTimestamp >= expiry) {
          this.untrackPendingTransaction(transaction);
        }
      }
    }
  }

  async startPendingTransactionExpiryLoop() {
    if (this.isActive) {
      this._pendingTransactionExpiryCheckIntervalId = setInterval(() => {
        this.expirePendingTransactionStreams(this.pendingTransactionExpiry);
      }, this.pendingTransactionExpiryCheckInterval);
    }
  }

  async updateModuleState(moduleState) {
    return this.channel.invoke('app:updateModuleState', {
      [this.alias]: moduleState
    });
  }

  async attemptGetSignedBlockAtHeight(height) {
    try {
      return await this.dal.getSignedBlockAtHeight(height);
    } catch (error) {
      if (error.name !== 'BlockDidNotExistError') {
        throw error;
      }
    }
    return null;
  }

  async getMaxForgerCountAtHeight(height) {
    let blockSampleSize = this.forgerCount * this.blockForgerSamplingFactor;
    let startHeight = Math.max(0, height - blockSampleSize);
    let blockList = await this.dal.getBlocksBetweenHeights(startHeight, height, blockSampleSize);
    let forgerSet = new Set();
    for (let block of blockList) {
      forgerSet.add(block.forgerAddress);
    }
    return forgerSet.size;
  }

  async checkGenesesConfig() {
    if (!this.genesesHeights.length) {
      throw new Error(
        'Geneses config was invalid - There must be at least one genesis'
      );
    }

    let lastGenesesHeight = this.genesesHeights[this.genesesHeights.length - 1];
    let maxBlockHeight = await this.dal.getMaxBlockHeight();

    let milestoneHeights = [...this.genesesHeights];
    if (maxBlockHeight > lastGenesesHeight) {
      milestoneHeights.push(maxBlockHeight);
    }
    let milestonesLength = milestoneHeights.length;

    for (let i = 1; i < milestonesLength; i++) {
      let rangeStartHeight = milestoneHeights[i - 1];

      let requiredSignatureCount = this.geneses[rangeStartHeight];
      let rangeEndHeight = milestoneHeights[i] - 1;
      let rangeHeightDiff = rangeEndHeight - rangeStartHeight;
      let rangeMidHeight = rangeStartHeight + Math.round(rangeHeightDiff / 2);

      let [ maxDelegateStartCount, maxDelegateMidCount, maxDelegateEndCount ] = await Promise.all([
        this.getMaxForgerCountAtHeight(rangeStartHeight),
        this.getMaxForgerCountAtHeight(rangeMidHeight),
        this.getMaxForgerCountAtHeight(rangeEndHeight)
      ]);

      // Subtract 1 from delegate counts because the forger cannot also be a signer; this means
      // that if there are x delegates, then the maximum possible number of signatures is x-1.
      let requiredStartSignatureCount = Math.min(
        Math.max(0, maxDelegateStartCount - 1),
        requiredSignatureCount
      );
      let requiredMidSignatureCount = Math.min(
        Math.max(0, maxDelegateMidCount - 1),
        requiredSignatureCount
      );
      let requiredEndSignatureCount = Math.min(
        Math.max(0, maxDelegateEndCount - 1),
        requiredSignatureCount
      );

      let [ startBlock, midBlock, endBlock ] = await Promise.all([
        this.attemptGetSignedBlockAtHeight(rangeStartHeight),
        this.attemptGetSignedBlockAtHeight(rangeMidHeight),
        this.attemptGetSignedBlockAtHeight(rangeEndHeight)
      ]);

      let unmetSignatureCountList = [];
      if (startBlock && startBlock.signatures.length < requiredStartSignatureCount) {
        unmetSignatureCountList.push(startBlock.signatures.length);
      }
      if (midBlock && midBlock.signatures.length < requiredMidSignatureCount) {
        unmetSignatureCountList.push(midBlock.signatures.length);
      }
      if (endBlock && endBlock.signatures.length < requiredEndSignatureCount) {
        unmetSignatureCountList.push(endBlock.signatures.length);
      }

      if (unmetSignatureCountList.length) {
        let minSignatureCount = Math.min(...unmetSignatureCountList);

        throw new Error(
          `The geneses config was invalid at height ${
            rangeStartHeight
          } - Node did not have a sufficient number of block signatures - Try lowering the signature requirement to ${
            minSignatureCount
          } for that height`
        );
      }
    }
  }

  async load(channel, options) {
    this.channel = channel;
    this.isActive = true;

    let defaultOptions = {
      forgingInterval: DEFAULT_FORGING_INTERVAL,
      forgerCount: DEFAULT_FORGER_COUNT,
      minForgerBlockSignatureRatio: DEFAULT_MIN_FORGER_BLOCK_SIGNATURE_RATIO,
      fetchBlockLimit: DEFAULT_FETCH_BLOCK_LIMIT,
      fetchBlockPause: DEFAULT_FETCH_BLOCK_PAUSE,
      blockProcessingFailurePause: DEFAULT_BLOCK_PROCESSING_FAILURE_PAUSE,
      fetchBlockEndConfirmations: DEFAULT_FETCH_BLOCK_END_CONFIRMATIONS,
      forgingBlockBroadcastDelay: DEFAULT_FORGING_BLOCK_BROADCAST_DELAY,
      forgingSignatureBroadcastDelay: DEFAULT_FORGING_SIGNATURE_BROADCAST_DELAY,
      autoSyncForgingKeyIndex: DEFAULT_AUTO_SYNC_FORGING_KEY_INDEX,
      propagationTimeout: DEFAULT_PROPAGATION_TIMEOUT,
      propagationRandomness: DEFAULT_PROPAGATION_RANDOMNESS,
      timePollInterval: DEFAULT_TIME_POLL_INTERVAL,
      minTransactionsPerBlock: DEFAULT_MIN_TRANSACTIONS_PER_BLOCK,
      maxTransactionsPerBlock: DEFAULT_MAX_TRANSACTIONS_PER_BLOCK,
      minMultisigMembers: DEFAULT_MIN_MULTISIG_MEMBERS,
      maxMultisigMembers: DEFAULT_MAX_MULTISIG_MEMBERS,
      minMultisigRegistrationFeePerMember: DEFAULT_MIN_MULTISIG_REGISTRATION_FEE_PER_MEMBER,
      minMultisigTransactionFeePerMember: DEFAULT_MIN_MULTISIG_TRANSACTION_FEE_PER_MEMBER,
      pendingTransactionSettlementDelay: DEFAULT_PENDING_TRANSACTION_SETTLEMENT_DELAY,
      pendingTransactionExpiry: DEFAULT_PENDING_TRANSACTION_EXPIRY,
      pendingTransactionExpiryCheckInterval: DEFAULT_PENDING_TRANSACTION_EXPIRY_CHECK_INTERVAL,
      maxSpendableDigits: DEFAULT_MAX_SPENDABLE_DIGITS,
      maxTransactionMessageLength: DEFAULT_MAX_TRANSACTION_MESSAGE_LENGTH,
      maxVotesPerAccount: DEFAULT_MAX_VOTES_PER_ACCOUNT,
      maxTransactionBackpressurePerAccount: DEFAULT_MAX_TRANSACTION_BACKPRESSURE_PER_ACCOUNT,
      maxPendingTransactionsPerAccount: DEFAULT_MAX_PENDING_TRANSACTIONS_PER_ACCOUNT,
      maxConsecutiveBlockFetchFailures: DEFAULT_MAX_CONSECUTIVE_BLOCK_FETCH_FAILURES,
      maxConsecutiveTransactionFetchFailures: DEFAULT_MAX_CONSECUTIVE_TRANSACTION_FETCH_FAILURES,
      catchUpConsensusPollCount: DEFAULT_CATCH_UP_CONSENSUS_POLL_COUNT,
      catchUpConsensusMinRatio: DEFAULT_CATCH_UP_CONSENSUS_MIN_RATIO,
      geneses: DEFAULT_GENESES,
      blockForgerSamplingFactor: DEFAULT_BLOCK_FORGER_SAMPLING_FACTOR,
      apiLimit: DEFAULT_API_LIMIT,
      maxPublicAPILimit: DEFAULT_MAX_PUBLIC_API_LIMIT,
      maxPrivateAPILimit: DEFAULT_MAX_PRIVATE_API_LIMIT,
      maxPublicAPIOffset: DEFAULT_MAX_PUBLIC_API_OFFSET,
      maxPrivateAPIOffset: DEFAULT_MAX_PRIVATE_API_OFFSET,
      keyIndexDirPath: DEFAULT_KEY_INDEX_DIR_PATH,
      keyIndexFileExtension: DEFAULT_KEY_INDEX_FILE_EXTENSION,
      keyIndexFileLockOptions: DEFAULT_KEY_INDEX_FILE_LOCK_OPTIONS
    };
    this.options = {...defaultOptions, ...options};
    this.chainInfo = {
      forgingInterval: this.options.forgingInterval,
      forgerCount: this.options.forgerCount,
      minForgerBlockSignatureRatio: this.options.minForgerBlockSignatureRatio,
      minTransactionsPerBlock: this.options.minTransactionsPerBlock,
      maxTransactionsPerBlock: this.options.maxTransactionsPerBlock,
      minMultisigMembers: this.options.minMultisigMembers,
      maxMultisigMembers: this.options.maxMultisigMembers,
      maxSpendableDigits: this.options.maxSpendableDigits,
      maxTransactionMessageLength: this.options.maxTransactionMessageLength,
      maxVotesPerAccount: this.options.maxVotesPerAccount,
      maxTransactionBackpressurePerAccount: this.options.maxTransactionBackpressurePerAccount,
      maxPendingTransactionsPerAccount: this.options.maxPendingTransactionsPerAccount
    };
    this.apiInfo = {
      apiLimit: this.options.apiLimit,
      maxPublicAPILimit: this.options.maxPublicAPILimit,
      maxPrivateAPILimit: this.options.maxPrivateAPILimit,
      maxPublicAPIOffset: this.options.maxPublicAPIOffset,
      maxPrivateAPIOffset: this.options.maxPrivateAPIOffset
    };

    let unsanitizedMinTransactionFees = {
      ...DEFAULT_MIN_TRANSACTION_FEES,
      ...this.options.minTransactionFees
    };
    let minTransactionFees = {};
    let transactionTypeList = Object.keys(unsanitizedMinTransactionFees);
    for (let transactionType of transactionTypeList) {
      minTransactionFees[transactionType] = BigInt(unsanitizedMinTransactionFees[transactionType]);
    }
    this.options.minTransactionFees = unsanitizedMinTransactionFees;
    this.minTransactionFees = minTransactionFees;
    this.minMultisigRegistrationFeePerMember = BigInt(this.options.minMultisigRegistrationFeePerMember);
    this.minMultisigTransactionFeePerMember = BigInt(this.options.minMultisigTransactionFeePerMember);

    this.forgingInterval = this.options.forgingInterval;
    this.forgerCount = this.options.forgerCount;
    this.minForgerBlockSignatureRatio = this.options.minForgerBlockSignatureRatio;
    this.autoSyncForgingKeyIndex = this.options.autoSyncForgingKeyIndex;
    this.propagationRandomness = this.options.propagationRandomness;
    this.minMultisigMembers = this.options.minMultisigMembers;
    this.maxMultisigMembers = this.options.maxMultisigMembers;
    this.minTransactionsPerBlock = this.options.minTransactionsPerBlock;
    this.maxTransactionsPerBlock = this.options.maxTransactionsPerBlock;
    this.pendingTransactionExpiry = this.options.pendingTransactionExpiry;
    this.pendingTransactionExpiryCheckInterval = this.options.pendingTransactionExpiryCheckInterval;
    this.maxSpendableDigits = this.options.maxSpendableDigits;
    this.maxTransactionMessageLength = this.options.maxTransactionMessageLength;
    this.maxVotesPerAccount = this.options.maxVotesPerAccount;
    this.maxTransactionBackpressurePerAccount = this.options.maxTransactionBackpressurePerAccount;
    this.maxPendingTransactionsPerAccount = this.options.maxPendingTransactionsPerAccount;
    this.maxConsecutiveTransactionFetchFailures = this.options.maxConsecutiveTransactionFetchFailures;
    this.geneses = this.options.geneses;
    this.genesesHeights = Object.keys(this.geneses).map(heightString => Number(heightString));
    this.blockForgerSamplingFactor = this.options.blockForgerSamplingFactor;
    this.apiLimit = this.options.apiLimit;
    this.maxPublicAPILimit = this.options.maxPublicAPILimit;
    this.maxPrivateAPILimit = this.options.maxPrivateAPILimit;
    this.maxPublicAPIOffset = this.options.maxPublicAPIOffset;
    this.maxPrivateAPIOffset = this.options.maxPrivateAPIOffset;

    if (this.minForgerBlockSignatureRatio < 0.5) {
      throw new Error(
        `The minForgerBlockSignatureRatio option cannot be less than 0.5`
      );
    }

    if (this.forgerCount > MAX_FORGER_COUNT) {
      throw new Error(
        `The forgerCount option cannot be greater than ${MAX_FORGER_COUNT}`
      );
    }

    this.genesis = require(
      this.options.genesisPath == null ? DEFAULT_GENESIS_PATH : path.resolve(this.options.genesisPath)
    );
    try {
      await this.dal.init({
        genesis: this.genesis,
        maxVotesPerAccount: this.maxVotesPerAccount
      });
    } catch (error) {
      throw new Error(
        `Failed to initialize from genesis because of error: ${error.message}`
      );
    }
    await this.checkGenesesConfig();

    this.networkSymbol = this.genesis.networkSymbol || DEFAULT_NETWORK_SYMBOL;

    this.cryptoClientLibPath = this.options.cryptoClientLibPath == null ?
      DEFAULT_CRYPTO_CLIENT_LIB_PATH : path.resolve(this.options.cryptoClientLibPath);
    let { createClient } = require(this.cryptoClientLibPath);

    this.ldposClient = createClient({
      adapter: this.dal,
      networkSymbol: this.networkSymbol,
      verifyNetwork: false,
      keyIndexDirPath: this.options.keyIndexDirPath,
      keyIndexFileExtension: this.options.keyIndexFileExtension,
      keyIndexFileLockOptions: this.options.keyIndexFileLockOptions
    });

    this.ldposForgingClients = {};
    let forgerInfoList = this.options.forgingCredentials || [];

    try {
      await Promise.all(
        forgerInfoList.map(async (forgerInfo) => {
          let forgingPassphrase = this.getForgingPassphrase(forgerInfo);
          let forgingClient = createClient({
            adapter: this.dal,
            networkSymbol: this.networkSymbol,
            verifyNetwork: false,
            keyIndexDirPath: this.options.keyIndexDirPath,
            keyIndexFileExtension: this.options.keyIndexFileExtension,
            keyIndexFileLockOptions: this.options.keyIndexFileLockOptions
          });
          await forgingClient.connect({
            passphrase: forgingPassphrase,
            walletAddress: forgerInfo.walletAddress,
            forgingKeyIndex: LDPOS_FORGING_KEY_INDEX == null ? null : Number(LDPOS_FORGING_KEY_INDEX)
          });
          let forgingWalletAddress = forgingClient.getWalletAddress();

          if (this.autoSyncForgingKeyIndex) {
            let wasKeyIndexUpdated = await forgingClient.syncKeyIndex('forging');
            if (wasKeyIndexUpdated) {
              this.logger.info(
                `The forging key index of delegate ${
                  forgingWalletAddress
                } was shifted to ${
                  forgingClient.forgingKeyIndex
                } during launch`
              );
            }
          }
          this.ldposForgingClients[forgingWalletAddress] = forgingClient;
        })
      );
    } catch (error) {
      throw new Error(
        `Failed to initialize forging because of error: ${error.message}`
      );
    }

    try {
      await this.fetchTopActiveDelegates();
    } catch (error) {
      throw new Error(
        `Failed to load top active delegates because of error: ${error.message}`
      );
    }

    this.nodeHeight = await this.dal.getMaxBlockHeight();
    try {
      this.lastProcessedBlock = await this.dal.getSignedBlockAtHeight(this.nodeHeight);
    } catch (error) {
      if (error.name !== 'BlockDidNotExistError') {
        throw new Error(
          `Failed to load last processed block because of error: ${error.message}`
        );
      }
    }
    if (!this.lastProcessedBlock) {
      this.lastProcessedBlock = {
        height: 0,
        timestamp: 0,
        transactions: [],
        previousBlockId: null,
        forgerAddress: null,
        forgingPublicKey: null,
        nextForgingPublicKey: null,
        nextForgingKeyIndex: null,
        id: null,
        forgerSignature: null,
        signatures: []
      };
    }
    this.lastReceivedBlock = this.lastProcessedBlock;
    this.lastHandledBlock = this.lastProcessedBlock;

    // Create an entry for each genesis height and each signature index so that
    // other peers can route requests to us based on which genesis starting points
    // we support and how many signatures we provide for each one.
    for (let genHeight of this.genesesHeights) {
      let signatureCount = this.geneses[genHeight];
      for (let i = 0; i <= signatureCount; i++) {
        this.moduleState[`${GENESIS_INDICATOR}${genHeight}-${i}`] = 1;
      }
    }

    await this.updateModuleState(this.moduleState);

    this.startPendingTransactionExpiryLoop();
    this.startTransactionPropagationLoop();
    this.startBlockPropagationLoop();
    this.startBlockSignaturePropagationLoop();
    this.startBlockProcessingLoop();

    this.publishToChannel(`${this.alias}:bootstrap`);
  }

  async publishToChannel(channelName, data) {
    try {
      await this.channel.publish(channelName, data);
    } catch (error) {
      this.logger.error(
        new Error(
          `Failed to publish to the ${channelName} channel because of error: ${
            error.message
          }`
        )
      );
    }
  }

  async clearAllData() {
    await this.dal.clearAllData();
  }

  async unload() {
    clearInterval(this._pendingTransactionExpiryCheckIntervalId);
    if (this.isActive) {
      this.isActive = false;
      await new Promise((resolve) => {
        this.resolveUnload = resolve;
      });
      await this.dal.destroy();
    }
  }

  async wait(duration) {
    return new Promise((resolve) => {
      setTimeout(resolve, duration);
    });
  }
};
