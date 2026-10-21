const assert = require('assert');
const Channel = require('./utils/channel');
const NetworkModule = require('./utils/network');
const AppModule = require('./utils/app');
const MockLDPoSChainModule = require('./utils/chain');
const wait = require('./utils/wait');
const { createClient } = require('ldpos-client');
const LDPoSChainModule = require('../index');

const { validateTransactionAmount, validateTransactionFee } = require('../schemas/primitives');
const { validateTransactionSchema } = require('../schemas/transaction-schema');
const { validateSigTransactionSchema } = require('../schemas/sig-transaction-schema');
const { validateMultisigTransactionSchema } = require('../schemas/multisig-transaction-schema');

const NETWORK_SYMBOL = 'ldpos';
const MAX_SPENDABLE_DIGITS = 25;
const MAX_TRANSACTION_MESSAGE_LENGTH = 256;
const MIN_MULTISIG_MEMBERS = 1;
const MAX_MULTISIG_MEMBERS = 100;
const FORGING_INTERVAL = 10000;

const FORGER_PASSPHRASE = 'clerk aware give dog reopen peasant duty cheese tobacco trouble gold angle';
const FORGER_ADDRESS = 'ldpos313ac2d3d1d081901be0c5ce074d1e81a8a0bf5f';
// Address: ldpos5f0bc55450657f7fcb188e90122f7e4cee894199
const WALLET_A_PASSPHRASE = 'birth select quiz process bid raccoon memory village snow cable agent bean';
const WALLET_A_ADDRESS = 'ldpos5f0bc55450657f7fcb188e90122f7e4cee894199';
const WALLET_B_ADDRESS = 'ldposaed82ed3f324e738306301ca4d6b955580d4bc24';

const useDal = process.env.USE_DAL;
const dalLibPath = useDal ? useDal : './test/utils/dal';

function makeAddress(fillChar) {
  return `${NETWORK_SYMBOL}${fillChar.repeat(40)}`;
}

function makePublicKey(fillChar) {
  return fillChar.repeat(64);
}

// Captures unhandled promise rejections which occur while the provided
// function runs. Mocha installs its own unhandledRejection listener, so it is
// temporarily detached to make the assertion inside the test authoritative.
async function captureUnhandledRejections(run) {
  let priorListeners = process.listeners('unhandledRejection');
  for (let listener of priorListeners) {
    process.removeListener('unhandledRejection', listener);
  }
  let capturedRejections = [];
  let capture = (error) => {
    capturedRejections.push(error);
  };
  process.on('unhandledRejection', capture);
  try {
    await run();
  } finally {
    process.removeListener('unhandledRejection', capture);
    for (let listener of priorListeners) {
      process.on('unhandledRejection', listener);
    }
  }
  return capturedRejections;
}

describe('Security regression tests', async () => {
  let chainModule;
  let channel;
  let adapter;
  let keyIndex;
  let keyManager;
  let logMessages;

  beforeEach(async () => {
    logMessages = {
      info: [],
      debug: [],
      warn: [],
      error: []
    };

    chainModule = new LDPoSChainModule({
      config: {
        components: {
          dal: {
            libPath: dalLibPath
          }
        }
      },
      logger: {
        info: (...args) => logMessages.info.push(args.join(' ')),
        debug: (...args) => logMessages.debug.push(args.map(arg => arg && arg.message || arg).join(' ')),
        warn: (...args) => logMessages.warn.push(args.map(arg => arg && arg.message || arg).join(' ')),
        error: (...args) => logMessages.error.push(args.map(arg => arg && arg.message || arg).join(' '))
      }
    });

    adapter = {
      getNetworkSymbol: async () => {
        return chainModule.actions.getNetworkSymbol.handler();
      },
      getAccount: async (walletAddress) => {
        return chainModule.actions.getAccount.handler({ params: { walletAddress } });
      },
      postTransaction: async (transaction) => {
        return chainModule.actions.postTransaction.handler({ params: { transaction } });
      }
    };

    keyIndex = 0;
    keyManager = {
      saveKeyIndex: async () => {},
      loadKeyIndex: async () => {
        return 0;
      },
      incrementKeyIndex: async () => {
        return keyIndex++;
      },
      deleteKeyIndex: async () => {}
    };

    channel = new Channel({
      modules: {
        app: new AppModule(),
        network: new NetworkModule({
          modules: {
            ldpos_chain: new MockLDPoSChainModule()
          }
        })
      }
    });
  });

  afterEach(async () => {
    // If load() threw part-way through, the block processing loop never
    // started, so nothing would ever resolve unload(). Short-circuit it.
    if (!chainModule.lastProcessedBlock) {
      chainModule.isActive = false;
    }
    await chainModule.unload();
  });

  // Loads the module and waits until the initial catch-up pass has finished.
  async function loadAndSettle(extraOptions) {
    await chainModule.clearAllData();
    await chainModule.load(channel, {
      genesisPath: './test/utils/genesis-functional.json',
      minTransactionsPerBlock: 0,
      forgingInterval: FORGING_INTERVAL,
      forgingBlockBroadcastDelay: 500,
      forgingSignatureBroadcastDelay: 2000,
      propagationRandomness: 100,
      propagationTimeout: 3000,
      ...extraOptions
    });
    for (let i = 0; i < 100; i++) {
      if (!chainModule.isCatchingUp) {
        return;
      }
      await wait(100);
    }
    throw new Error('Timed out waiting for the node to finish catching up');
  }

  describe('1. Transaction amount and fee sign validation', async () => {

    it('should reject a negative transaction amount at the schema level', async () => {
      assert.throws(
        () => validateTransactionAmount('amount', { amount: '-1' }, MAX_SPENDABLE_DIGITS),
        /negative/
      );
      assert.throws(
        () => validateTransactionAmount('amount', { amount: '-999999999999999999' }, MAX_SPENDABLE_DIGITS),
        /negative/
      );
      // Zero and positive amounts must still be accepted.
      validateTransactionAmount('amount', { amount: '0' }, MAX_SPENDABLE_DIGITS);
      validateTransactionAmount('amount', { amount: '100000000' }, MAX_SPENDABLE_DIGITS);
    });

    it('should reject a negative transaction fee at the schema level', async () => {
      assert.throws(
        () => validateTransactionFee('fee', { fee: '-1' }, MAX_SPENDABLE_DIGITS),
        /negative/
      );
      validateTransactionFee('fee', { fee: '0' }, MAX_SPENDABLE_DIGITS);
      validateTransactionFee('fee', { fee: '10000000' }, MAX_SPENDABLE_DIGITS);
    });

    it('should reject a transfer transaction with a negative amount during block verification', async () => {
      let transaction = {
        id: 'a'.repeat(40),
        type: 'transfer',
        senderAddress: WALLET_A_ADDRESS,
        recipientAddress: WALLET_B_ADDRESS,
        amount: '-15000000000',
        fee: '10000000',
        timestamp: 100000,
        message: '',
        sigPublicKey: makePublicKey('1'),
        nextSigPublicKey: makePublicKey('2'),
        nextSigKeyIndex: 1,
        senderSignature: 'abc'
      };

      assert.throws(
        () => validateTransactionSchema(
          transaction,
          MAX_SPENDABLE_DIGITS,
          NETWORK_SYMBOL,
          MAX_TRANSACTION_MESSAGE_LENGTH,
          MIN_MULTISIG_MEMBERS,
          MAX_MULTISIG_MEMBERS
        ),
        /negative/
      );
    });

    it('should not treat a negative transaction total as affordable', async () => {
      let senderAccount = {
        address: WALLET_A_ADDRESS,
        balance: 100000000000n
      };

      assert.throws(
        () => chainModule.verifyAccountMeetsRequirements(senderAccount, {
          senderAddress: WALLET_A_ADDRESS,
          amount: '-15000000000',
          fee: '10000000'
        }),
        /cannot be negative/
      );

      // A transaction which the sender can afford must still be accepted.
      let txnTotal = chainModule.verifyAccountMeetsRequirements(senderAccount, {
        senderAddress: WALLET_A_ADDRESS,
        amount: '100000000',
        fee: '10000000'
      });
      assert.equal(txnTotal, 110000000n);
    });

    it('should not let a negative amount transfer credit the sender and debit the recipient', async () => {
      await loadAndSettle();

      let clientA = createClient({ adapter, keyManager, networkSymbol: NETWORK_SYMBOL });
      await clientA.connect({ passphrase: WALLET_A_PASSPHRASE });

      let balancesBefore = {
        sender: (await chainModule.actions.getAccount.handler({
          params: { walletAddress: WALLET_A_ADDRESS }
        })).balance,
        recipient: (await chainModule.actions.getAccount.handler({
          params: { walletAddress: WALLET_B_ADDRESS }
        })).balance
      };

      let preparedTxn = await clientA.prepareTransaction({
        type: 'transfer',
        recipientAddress: WALLET_B_ADDRESS,
        amount: '-15000000000',
        fee: '10000000',
        timestamp: 100000,
        message: ''
      });

      let postError = null;
      try {
        await chainModule.actions.postTransaction.handler({
          params: { transaction: preparedTxn }
        });
      } catch (error) {
        postError = error;
      }

      assert.notEqual(postError, null, 'Expected the negative amount transfer to be rejected');
      assert.equal(postError.type, 'InvalidActionError');
      assert.equal(/negative/.test(postError.message), true);

      assert.equal(chainModule.pendingTransactionMap.has(preparedTxn.id), false);

      let balancesAfter = {
        sender: (await chainModule.actions.getAccount.handler({
          params: { walletAddress: WALLET_A_ADDRESS }
        })).balance,
        recipient: (await chainModule.actions.getAccount.handler({
          params: { walletAddress: WALLET_B_ADDRESS }
        })).balance
      };

      assert.equal(balancesAfter.sender, balancesBefore.sender);
      assert.equal(balancesAfter.recipient, balancesBefore.recipient);
    }).timeout(30000);

  });

  describe('2. Malformed block signature received from a peer', async () => {

    it('should not raise an unhandled rejection when a peer sends a malformed block signature', async () => {
      await loadAndSettle();

      let capturedRejections = await captureUnhandledRejections(async () => {
        channel.emitter.emit(
          `network:event:${chainModule.alias}:blockSignature`,
          { data: { junk: true } }
        );
        await wait(1000);
      });

      assert.deepEqual(
        capturedRejections.map(error => error && error.message),
        [],
        'A malformed block signature must not produce an unhandled rejection'
      );
      assert.equal(
        logMessages.debug.some(message => /invalid delegate block signature/i.test(message)),
        true,
        'The malformed block signature should have been logged and discarded'
      );
    }).timeout(30000);

    it('should not raise an unhandled rejection when a peer sends an empty block signature', async () => {
      await loadAndSettle();

      let capturedRejections = await captureUnhandledRejections(async () => {
        for (let malformedSignature of [null, undefined, 'not-an-object', 42, []]) {
          channel.emitter.emit(
            `network:event:${chainModule.alias}:blockSignature`,
            { data: malformedSignature }
          );
        }
        await wait(1000);
      });

      assert.deepEqual(
        capturedRejections.map(error => error && error.message),
        [],
        'Malformed block signatures must not produce unhandled rejections'
      );
    }).timeout(30000);

  });

  describe('3. Transactions which mix sig and multisig signature properties', async () => {

    it('should reject a sig transaction which also carries a signatures property', async () => {
      let partialCheckTransaction = {
        sigPublicKey: makePublicKey('1'),
        nextSigPublicKey: makePublicKey('2'),
        nextSigKeyIndex: 1,
        senderSignatureHash: 'h'.repeat(44),
        signatures: []
      };
      assert.throws(
        () => validateSigTransactionSchema(partialCheckTransaction, false),
        /signatures/
      );

      let fullCheckTransaction = {
        sigPublicKey: makePublicKey('1'),
        nextSigPublicKey: makePublicKey('2'),
        nextSigKeyIndex: 1,
        senderSignature: 'abc',
        signatures: [{ signerAddress: WALLET_B_ADDRESS }]
      };
      assert.throws(
        () => validateSigTransactionSchema(fullCheckTransaction, true),
        /signatures/
      );
    });

    it('should still accept a well formed sig transaction', async () => {
      validateSigTransactionSchema({
        sigPublicKey: makePublicKey('1'),
        nextSigPublicKey: makePublicKey('2'),
        nextSigKeyIndex: 1,
        senderSignature: 'abc'
      }, true);

      validateSigTransactionSchema({
        sigPublicKey: makePublicKey('1'),
        nextSigPublicKey: makePublicKey('2'),
        nextSigKeyIndex: 1,
        senderSignatureHash: 'h'.repeat(44)
      }, false);
    });

    it('should reject a multisig transaction which also carries sig signature properties', async () => {
      let makeMultisigTransaction = (extraProperties) => {
        return {
          signatures: [
            {
              signerAddress: WALLET_B_ADDRESS,
              multisigPublicKey: makePublicKey('1'),
              nextMultisigPublicKey: makePublicKey('2'),
              nextMultisigKeyIndex: 1,
              signature: 'abc'
            }
          ],
          ...extraProperties
        };
      };

      assert.throws(
        () => validateMultisigTransactionSchema(
          makeMultisigTransaction({ senderSignature: 'abc' }),
          1,
          MAX_MULTISIG_MEMBERS,
          NETWORK_SYMBOL,
          true
        ),
        /senderSignature/
      );

      assert.throws(
        () => validateMultisigTransactionSchema(
          makeMultisigTransaction({ senderSignatureHash: 'h'.repeat(44) }),
          1,
          MAX_MULTISIG_MEMBERS,
          NETWORK_SYMBOL,
          true
        ),
        /senderSignatureHash/
      );

      assert.throws(
        () => validateMultisigTransactionSchema(
          makeMultisigTransaction({ sigPublicKey: makePublicKey('1') }),
          1,
          MAX_MULTISIG_MEMBERS,
          NETWORK_SYMBOL,
          true
        ),
        /sigPublicKey/
      );
    });

    it('should still accept a well formed multisig transaction', async () => {
      validateMultisigTransactionSchema({
        signatures: [
          {
            signerAddress: WALLET_B_ADDRESS,
            multisigPublicKey: makePublicKey('1'),
            nextMultisigPublicKey: makePublicKey('2'),
            nextMultisigKeyIndex: 1,
            signature: 'abc'
          }
        ]
      }, 1, MAX_MULTISIG_MEMBERS, NETWORK_SYMBOL, true);
    });

    it('should discard a forged block whose sig transaction carries a decoy signatures array', async () => {
      await loadAndSettle({ forgingCredentials: [] });

      let clientA = createClient({ adapter, keyManager, networkSymbol: NETWORK_SYMBOL });
      await clientA.connect({ passphrase: WALLET_A_PASSPHRASE });

      let preparedTxn = await clientA.prepareTransaction({
        type: 'transfer',
        recipientAddress: WALLET_B_ADDRESS,
        amount: '100000000',
        fee: '10000000',
        timestamp: 100000,
        message: ''
      });
      await chainModule.actions.postTransaction.handler({
        params: { transaction: preparedTxn }
      });
      assert.equal(chainModule.pendingTransactionMap.has(preparedTxn.id), true);

      let delegateClient = createClient({ adapter, keyManager, networkSymbol: NETWORK_SYMBOL });
      await delegateClient.connect({ passphrase: FORGER_PASSPHRASE });

      // Wait until we are early enough in the current time slot.
      while (Date.now() % FORGING_INTERVAL > FORGING_INTERVAL / 2) {
        await wait(200);
      }

      let pendingTxn = chainModule.pendingTransactionMap.get(preparedTxn.id);
      let blockTransaction = chainModule.simplifyTransaction(pendingTxn, true);
      blockTransaction.signatures = [];

      let maliciousBlock = await delegateClient.prepareBlock({
        height: 1,
        timestamp: chainModule.getCurrentBlockTimeSlot(FORGING_INTERVAL),
        previousBlockId: null,
        numberOfTransactions: 1,
        transactions: [blockTransaction]
      });

      let capturedRejections = await captureUnhandledRejections(async () => {
        channel.emitter.emit(
          `network:event:${chainModule.alias}:block`,
          { data: maliciousBlock }
        );
        await wait(2000);
      });

      assert.deepEqual(
        capturedRejections.map(error => error && error.message),
        [],
        'A block with a mismatched transaction must not produce an unhandled rejection'
      );

      // The block must not have been accepted.
      assert.notEqual(chainModule.lastReceivedBlock.id, maliciousBlock.id);
      let maxHeight = await chainModule.actions.getMaxBlockHeight.handler({ params: {} });
      assert.equal(maxHeight, 0);
    }).timeout(40000);

  });

  describe('4. Pending transaction fee ordering', async () => {

    it('should order transaction groups by true average fee instead of concatenated fee strings', async () => {
      let lowFeeAddress = makeAddress('a');
      let highFeeAddress = makeAddress('b');
      let lowFeePublicKey = makePublicKey('1');
      let highFeePublicKey = makePublicKey('2');

      let senderAccountDetails = {
        [lowFeeAddress]: {
          senderAccount: {
            address: lowFeeAddress,
            sigPublicKey: lowFeePublicKey,
            nextSigPublicKey: makePublicKey('3')
          },
          multisigMemberAccounts: null
        },
        [highFeeAddress]: {
          senderAccount: {
            address: highFeeAddress,
            sigPublicKey: highFeePublicKey,
            nextSigPublicKey: makePublicKey('4')
          },
          multisigMemberAccounts: null
        }
      };

      let transactions = [
        {
          id: 'a1',
          senderAddress: lowFeeAddress,
          sigPublicKey: lowFeePublicKey,
          nextSigKeyIndex: 1,
          fee: '10000000'
        },
        {
          id: 'a2',
          senderAddress: lowFeeAddress,
          sigPublicKey: lowFeePublicKey,
          nextSigKeyIndex: 2,
          fee: '10000000'
        },
        {
          id: 'b1',
          senderAddress: highFeeAddress,
          sigPublicKey: highFeePublicKey,
          nextSigKeyIndex: 1,
          fee: '900000000'
        }
      ];

      let sortedTransactions = chainModule.getSortedPendingTransactions(transactions, senderAccountDetails);

      assert.equal(sortedTransactions.length, 3);
      assert.equal(
        sortedTransactions[0].senderAddress,
        highFeeAddress,
        'The group with the highest average fee must be ordered first'
      );
      assert.equal(sortedTransactions[0].id, 'b1');
      assert.equal(sortedTransactions[1].senderAddress, lowFeeAddress);
      assert.equal(sortedTransactions[2].senderAddress, lowFeeAddress);
    });

    it('should order transactions within a group by signature key index', async () => {
      let senderAddress = makeAddress('a');
      let sigPublicKey = makePublicKey('1');

      let senderAccountDetails = {
        [senderAddress]: {
          senderAccount: {
            address: senderAddress,
            sigPublicKey,
            nextSigPublicKey: makePublicKey('2')
          },
          multisigMemberAccounts: null
        }
      };

      let transactions = [
        { id: 'third', senderAddress, sigPublicKey, nextSigKeyIndex: 9, fee: '10000000' },
        { id: 'first', senderAddress, sigPublicKey, nextSigKeyIndex: 1, fee: '10000000' },
        { id: 'second', senderAddress, sigPublicKey, nextSigKeyIndex: 4, fee: '10000000' }
      ];

      let sortedTransactions = chainModule.getSortedPendingTransactions(transactions, senderAccountDetails);

      assert.deepEqual(
        sortedTransactions.map(txn => txn.id),
        ['first', 'second', 'third']
      );
    });

    it('should handle fees which exceed the safe integer range', async () => {
      let firstAddress = makeAddress('a');
      let secondAddress = makeAddress('b');
      let firstPublicKey = makePublicKey('1');
      let secondPublicKey = makePublicKey('2');

      let senderAccountDetails = {
        [firstAddress]: {
          senderAccount: {
            address: firstAddress,
            sigPublicKey: firstPublicKey,
            nextSigPublicKey: makePublicKey('3')
          },
          multisigMemberAccounts: null
        },
        [secondAddress]: {
          senderAccount: {
            address: secondAddress,
            sigPublicKey: secondPublicKey,
            nextSigPublicKey: makePublicKey('4')
          },
          multisigMemberAccounts: null
        }
      };

      // These two fees are equal as doubles but differ as big integers.
      let transactions = [
        {
          id: 'lower',
          senderAddress: firstAddress,
          sigPublicKey: firstPublicKey,
          nextSigKeyIndex: 1,
          fee: '9007199254740993'
        },
        {
          id: 'higher',
          senderAddress: secondAddress,
          sigPublicKey: secondPublicKey,
          nextSigKeyIndex: 1,
          fee: '9007199254740995'
        }
      ];

      let sortedTransactions = chainModule.getSortedPendingTransactions(transactions, senderAccountDetails);

      assert.deepEqual(
        sortedTransactions.map(txn => txn.id),
        ['higher', 'lower']
      );
    });

  });

  describe('5. Geneses config height ordering', async () => {

    it('should sort geneses heights numerically rather than lexicographically', async () => {
      await loadAndSettle({
        geneses: {
          0: 0,
          9: 0,
          10: 0,
          100: 0
        }
      });

      assert.deepEqual(chainModule.genesesHeights, [0, 9, 10, 100]);
    }).timeout(30000);

    it('should reject a geneses config whose signature requirement decreases as height increases', async () => {
      let loadError = null;
      try {
        await loadAndSettle({
          geneses: {
            0: 1,
            9: 9,
            10: 2,
            100: 3
          }
        });
      } catch (error) {
        loadError = error;
      }

      assert.notEqual(loadError, null, 'Expected the decreasing geneses config to be rejected');
      assert.equal(
        /Signature requirement cannot decrease as height increases/.test(loadError.message),
        true,
        `Unexpected error message: ${loadError.message}`
      );
    }).timeout(30000);

    it('should accept a geneses config whose signature requirement does not decrease', async () => {
      await loadAndSettle({
        geneses: {
          0: 0,
          9: 0,
          10: 0,
          100: 0
        }
      });

      assert.deepEqual(chainModule.genesesHeights, [0, 9, 10, 100]);
    }).timeout(30000);

  });

  describe('6. postTransaction with a missing transaction', async () => {

    it('should report that the transaction was not specified instead of dereferencing it', async () => {
      await loadAndSettle();

      let postError = null;
      try {
        await chainModule.actions.postTransaction.handler({ params: {} });
      } catch (error) {
        postError = error;
      }

      assert.notEqual(postError, null, 'Expected postTransaction to reject');
      assert.equal(postError.name, 'InvalidTransactionError');
      assert.equal(postError.type, 'InvalidActionError');
      assert.equal(
        /Cannot read propert/.test(postError.message),
        false,
        `Expected a validation error but got a dereference error: ${postError.message}`
      );
      assert.equal(
        /was not specified/.test(postError.message),
        true,
        `Unexpected error message: ${postError.message}`
      );
    }).timeout(30000);

    it('should reject non-object transactions without dereferencing them', async () => {
      await loadAndSettle();

      for (let invalidTransaction of [null, 0, '', 'nope', []]) {
        let postError = null;
        try {
          await chainModule.actions.postTransaction.handler({
            params: { transaction: invalidTransaction }
          });
        } catch (error) {
          postError = error;
        }
        assert.notEqual(
          postError,
          null,
          `Expected postTransaction to reject ${JSON.stringify(invalidTransaction)}`
        );
        assert.equal(
          /Cannot read propert/.test(postError.message),
          false,
          `Expected a validation error but got a dereference error: ${postError.message}`
        );
      }
    }).timeout(30000);

  });

});
