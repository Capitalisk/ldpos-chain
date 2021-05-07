const assert = require('assert');
const Channel = require('./utils/channel');
const NetworkModule = require('./utils/network');
const AppModule = require('./utils/app');
const MockLDPoSChainModule = require('./utils/chain');
const { sha256 } = require('./utils/hash');
const wait = require('./utils/wait');
const { createClient } = require('ldpos-client');

const LDPoSChainModule = require('../index');

const NETWORK_SYMBOL = 'ldpos';

const useKnexDal = process.env.USE_KNEX_DAL;
const dalLibPath = useKnexDal ? 'ldpos-knex-dal' : './test/utils/dal';

// This test suite can be adapted to check whether or not a custom chain module is compatible with Lisk DEX.
// All the boilerplate can be modified except the 'it' blocks where the assertions are made.
// If a module passes all the test case cases in this file, then it is compatible with Lisk DEX.

describe('DEX API tests', async () => {
  let chainModule;
  let dal;
  let adapter;
  let store;
  let channel;
  let options;
  let bootstrapEventTriggered;
  let clientForger;
  let chainChangeEvents;
  let launchChainModule;

  beforeEach(async () => {
    chainModule = new LDPoSChainModule({
      config: {
        components: {
          dal: {
            libPath: dalLibPath
          }
        }
      },
      logger: {
        info: () => {},
        // info: (...args) => console.info.apply(console, args),
        debug: () => {},
        // debug: (...args) => console.debug.apply(console, args),
        warn: (...args) => console.warn.apply(console, args),
        error: (...args) => console.error.apply(console, args)
      }
    });

    dal = chainModule.dal;

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

    store = {
      saveItem: async () => {},
      loadItem: async () => {
        return '0';
      },
      deleteItem: async () => {}
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

    launchChainModule = async (moduleOptions) => {
      await chainModule.clearAllData();

      bootstrapEventTriggered = false;
      channel.subscribe(`${chainModule.alias}:bootstrap`, async () => {
        bootstrapEventTriggered = true;
      });

      chainChangeEvents = [];
      channel.subscribe(`${chainModule.alias}:chainChanges`, async (event) => {
        chainChangeEvents.push(event);
      });
      await chainModule.load(channel, moduleOptions);
      clientForger = createClient({
        adapter,
        store,
        networkSymbol: NETWORK_SYMBOL
      });
      await clientForger.connect({
        passphrase: moduleOptions.forgingCredentials[0].forgingPassphrase
      });
    };
  });

  afterEach(async () => {
    await chainModule.unload();
  });

  describe('module state', async () => {

    beforeEach(async () => {
      options = {
        genesisPath: './test/utils/genesis-dex-api.json',
        forgingCredentials: [
          {
            forgingPassphrase: 'clerk aware give dog reopen peasant duty cheese tobacco trouble gold angle'
          }
        ],
        minTransactionsPerBlock: 0, // Enable forging empty blocks.
        forgingInterval: 30000,
        forgingBlockBroadcastDelay: 200,
        forgingSignatureBroadcastDelay: 200,
        propagationRandomness: 100,
        propagationTimeout: 5000
      };
      await launchChainModule(options);
    });

    it('should expose an info property', async () => {
      let moduleInfo = chainModule.info;
      assert.equal(!!moduleInfo.author, true);
      assert.equal(!!moduleInfo.version, true);
      assert.equal(!!moduleInfo.name, true);
    });

    it('should expose an alias property', async () => {
      assert.equal(!!chainModule.alias, true);
    });

    it('should expose an events property', async () => {
      let events = chainModule.events;
      assert.equal(events.includes('bootstrap'), true);
      assert.equal(events.includes('chainChanges'), true);
    });

  });

  describe('module actions', async () => {

    let memberAddessList;
    let memberAccounts = [];
    let multisigAccount;
    let blockList = [];

    let clientA;
    let multisigMemberAPassphrase;
    let clientB;
    let multisigMemberBPassphrase;

    beforeEach(async () => {
      options = {
        genesisPath: './test/utils/genesis-dex-api.json',
        forgingCredentials: [
          {
            forgingPassphrase: 'clerk aware give dog reopen peasant duty cheese tobacco trouble gold angle'
          }
        ],
        minTransactionsPerBlock: 0, // Enable forging empty blocks.
        forgingInterval: 30000,
        forgingBlockBroadcastDelay: 200,
        forgingSignatureBroadcastDelay: 200,
        propagationRandomness: 100,
        propagationTimeout: 5000
      };
      await launchChainModule(options);

      multisigMemberAPassphrase = 'birth select quiz process bid raccoon memory village snow cable agent bean';
      multisigMemberBPassphrase = 'genius shoulder into daring armor proof cycle bench patrol paper grant picture';

      // Passphrase: panic test motion image soldier cloth script spice trigger magnet accident add
      multisigAccount = {
        address: 'ldpos17475c261ba8b5b7653700dfda1a2952053a4400',
        type: 'multisig',
        forgingPublicKey: 'KSxPdmjDS1LKGraH7fD9HjtjAYc6Y+H7O5ON0y90M9w=',
        nextForgingKeyIndex: 0,
        multisigPublicKey: 'KDlcXmucsuE5VS1WKUCCA2doLRS9U4rOxqzEtnnySfg=',
        nextMultisigKeyIndex: 0,
        sigPublicKey: 'F0dcJhuotbdlNwDf2hopUgU6RADv2MnL1LvYaRLEpBk=',
        nextSigKeyIndex: 0,
        balance: '100000000000'
      };

      memberAccounts = [
        // Passphrase: birth select quiz process bid raccoon memory village snow cable agent bean
        {
          address: 'ldpos5f0bc55450657f7fcb188e90122f7e4cee894199',
          type: 'sig',
          forgingPublicKey: 'e6c87420fb00ac4cd1327dabcfcfea7c2a63d3cf93580c18de2282385d3d72b3',
          nextForgingKeyIndex: 0,
          multisigPublicKey: 'a2d6e3024059ca92409911e0ad8308011f39c9278662f27ba7e32e1d777326dd',
          nextMultisigKeyIndex: 0,
          sigPublicKey: '1f4db4c3ae469a987776493d47a81a70c245ed00c9d4dd7ea5e6f39bde04a3d5',
          nextSigKeyIndex: 0,
          balance: '10000000000'
        },
        // Passphrase: genius shoulder into daring armor proof cycle bench patrol paper grant picture
        {
          address: 'ldpos3a7bb5751c811b76bf13edce4105b5b330a71054',
          type: 'sig',
          forgingPublicKey: 'SzXp6/L1ZztVN/LKxkkYQHR9BKoUuf1hjFf0a8vkZIE=',
          nextForgingKeyIndex: 0,
          multisigPublicKey: 'Zzqtg8AErQsUHSIiDFFX8O72WqhkzKgRFcZazfupOLM=',
          nextMultisigKeyIndex: 0,
          sigPublicKey: 'dy4ld4o23DOnwAEVRx0nDq0UWMFwsiLpxj8X2liN2e0=',
          nextSigKeyIndex: 0,
          balance: '20000000000'
        },
        // Passphrase: emotion belt burden flash vital neglect old census dress kid ocean warfare
        {
          address: 'ldpos708fc8aa632c697cb4239aba8e2b6b55a3a2824b',
          type: 'sig',
          forgingPublicKey: 'a8b9hWja0sLqsynJ+edM0N8rNUWQaIRbhfi/P0Njfkw=',
          nextForgingKeyIndex: 0,
          multisigPublicKey: 'lik8+MS783g9rqqqki1aZm7spwIfr/Uog+sKN50tK6Y=',
          nextMultisigKeyIndex: 0,
          sigPublicKey: 'cI/IqmMsaXy0I5q6jitrVaOigksGH6TdUAIH001FCtA=',
          nextSigKeyIndex: 0,
          balance: '30000000000'
        }
      ];

      memberAddessList = memberAccounts.map(account => account.address);
      for (let account of memberAccounts) {
        await dal.upsertAccount(account);
      }
      await dal.upsertAccount(multisigAccount);
      await dal.registerMultisigWallet(multisigAccount.address, memberAddessList, 2);

      clientA = createClient({
        adapter,
        store,
        networkSymbol: NETWORK_SYMBOL
      });
      await clientA.connect({
        passphrase: multisigMemberAPassphrase
      });

      clientB = createClient({
        adapter,
        store,
        networkSymbol: NETWORK_SYMBOL
      });
      await clientB.connect({
        passphrase: multisigMemberBPassphrase
      });

      let lastBlockId = null;
      let blockData = [
        {
          height: 1,
          timestamp: 30000,
          previousBlockId: null,
          transactions: [
            {
              type: 'transfer',
              recipientAddress: 'ldpos3a7bb5751c811b76bf13edce4105b5b330a71054',
              amount: '1100000000',
              fee: '100000000',
              timestamp: 10000,
              message: '0'
            },
            {
              type: 'transfer',
              recipientAddress: 'ldpos5f0bc55450657f7fcb188e90122f7e4cee894199',
              amount: '1200000000',
              fee: '100000000',
              timestamp: 20000,
              message: '1'
            }
          ]
        },
        {
          height: 2,
          timestamp: 60000,
          previousBlockId: null,
          transactions: [
            {
              type: 'transfer',
              recipientAddress: 'ldpos5f0bc55450657f7fcb188e90122f7e4cee894199',
              amount: '1300000000',
              fee: '100000000',
              timestamp: 30000,
              message: '2'
            }
          ]
        },
        {
          height: 3,
          timestamp: 90000,
          previousBlockId: null,
          transactions: [
            {
              type: 'transfer',
              recipientAddress: 'ldpos5f0bc55450657f7fcb188e90122f7e4cee894199',
              amount: '1300000000',
              fee: '100000000',
              timestamp: 80000,
              message: '3'
            }
          ]
        }
      ];

      blockList = await Promise.all(
        blockData.map(async (block) => {
          block.previousBlockId = lastBlockId;
          let preparedBlock = await clientForger.prepareBlock(block);
          let { transactions, ...preparedBlockWithoutTxns } = preparedBlock;
          lastBlockId = preparedBlockWithoutTxns.id;

          if (block.height === 3) {
            return {
              height: preparedBlockWithoutTxns.height,
              timestamp: preparedBlockWithoutTxns.timestamp,
              previousBlockId: preparedBlockWithoutTxns.previousBlockId,
              transactions: await Promise.all(
                transactions.map(async (txn) => {
                  let multisigTxn = clientForger.prepareMultisigTransaction(txn);
                  let signatureA = await clientA.signMultisigTransaction(multisigTxn);
                  let signatureB = await clientB.signMultisigTransaction(multisigTxn);
                  multisigTxn.signatures = [signatureA, signatureB];
                  return chainModule.simplifyTransaction(multisigTxn, true);
                })
              ),
              ...preparedBlockWithoutTxns
            };
          }

          return {
            height: preparedBlockWithoutTxns.height,
            timestamp: preparedBlockWithoutTxns.timestamp,
            previousBlockId: preparedBlockWithoutTxns.previousBlockId,
            transactions: await Promise.all(
              transactions.map(
                async (txn) => chainModule.simplifyTransaction(await clientForger.prepareTransaction(txn), true)
              )
            ),
            ...preparedBlockWithoutTxns
          };
        })
      );

      for (let block of blockList) {
        await dal.upsertBlock(block);
      }
    });

    describe('getMultisigWalletMembers action', async () => {

      it('should return an array of member addresses', async () => {
        let walletMembers = await chainModule.actions.getMultisigWalletMembers.handler({
          params: {
            walletAddress: multisigAccount.address
          }
        });
        // Must be an array of wallet address strings.
        assert.equal(JSON.stringify(walletMembers), JSON.stringify(memberAddessList));
      });

      it('should throw a MultisigAccountDidNotExistError if the multisig wallet address does not exist', async () => {
        let caughtError = null;
        try {
          await chainModule.actions.getMultisigWalletMembers.handler({
            params: {
              walletAddress: 'ldpos6312b77c6ca4233141835eb37f8f33a45f18d50f'
            }
          });
        } catch (error) {
          caughtError = error;
        }
        assert.notEqual(caughtError, null);
        assert.equal(caughtError.type, 'InvalidActionError');
        assert.equal(caughtError.name, 'MultisigAccountDidNotExistError');
      });

    });

    describe('getMinMultisigRequiredSignatures action', async () => {

      it('should return the number of required signatures', async () => {
        let requiredSignatureCount = await chainModule.actions.getMinMultisigRequiredSignatures.handler({
          params: {
            walletAddress: multisigAccount.address
          }
        });
        assert.equal(requiredSignatureCount, 2);
      });

      it('should throw an AccountDidNotExistError if the wallet address does not exist', async () => {
        let caughtError = null;
        try {
          await chainModule.actions.getMinMultisigRequiredSignatures.handler({
            params: {
              walletAddress: 'ldpos6312b77c6ca4233141835eb37f8f33a45f18d50f'
            }
          });
        } catch (error) {
          caughtError = error;
        }
        assert.notEqual(caughtError, null);
        assert.equal(caughtError.type, 'InvalidActionError');
        assert.equal(caughtError.name, 'AccountDidNotExistError');
      });

      it('should throw an AccountWasNotMultisigError if the account is not a multisig wallet', async () => {
        let caughtError = null;
        try {
          await chainModule.actions.getMinMultisigRequiredSignatures.handler({
            params: {
              walletAddress: 'ldpos5f0bc55450657f7fcb188e90122f7e4cee894199'
            }
          });
        } catch (error) {
          caughtError = error;
        }
        assert.notEqual(caughtError, null);
        assert.equal(caughtError.type, 'InvalidActionError');
        assert.equal(caughtError.name, 'AccountWasNotMultisigError');
      });

    });

    describe('getOutboundTransactions action', async () => {

      it('should return an array of transactions sent from the specified walletAddress', async () => {
        let transactions = await chainModule.actions.getOutboundTransactions.handler({
          params: {
            walletAddress: clientForger.walletAddress,
            fromTimestamp: 0,
            limit: 100
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 4);
        assert.equal(transactions[0].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[0].message, '0');
        assert.equal(transactions[1].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[1].message, '1');
        assert.equal(transactions[2].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[2].message, '2');
        assert.equal(transactions[3].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[3].message, '3');

        for (let txn of transactions) {
          assert.equal(typeof txn.id, 'string');
          assert.equal(typeof txn.message, 'string');
          assert.equal(typeof txn.amount, 'string');
          assert.equal(Number.isNaN(Number(txn.amount)), false);
          assert.equal(Number.isInteger(txn.timestamp), true);
        }
      });

      it('should return transactions which are more recent than fromTimestamp by default', async () => {
        let transactions = await chainModule.actions.getOutboundTransactions.handler({
          params: {
            walletAddress: clientForger.walletAddress,
            fromTimestamp: 15000,
            limit: 100
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 3);
        assert.equal(transactions[0].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[0].message, '1');
        assert.equal(transactions[1].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[1].message, '2');
        assert.equal(transactions[2].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[2].message, '3');
      });

      it('should return transactions which are more recent than fromTimestamp when order is desc', async () => {
        let transactions = await chainModule.actions.getOutboundTransactions.handler({
          params: {
            walletAddress: clientForger.walletAddress,
            fromTimestamp: 40000,
            limit: 100,
            order: 'desc'
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 3);
        assert.equal(transactions[0].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[0].message, '2');
        assert.equal(transactions[1].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[1].message, '1');
        assert.equal(transactions[2].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[2].message, '0');
      });

      it('should limit the number of transactions based on the specified limit', async () => {
        let transactions = await chainModule.actions.getOutboundTransactions.handler({
          params: {
            walletAddress: clientForger.walletAddress,
            fromTimestamp: 0,
            limit: 1
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 1);
        assert.equal(transactions[0].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[0].message, '0');
      });

      it('should return an empty array if no transactions can be matched', async () => {
        let transactions = await chainModule.actions.getOutboundTransactions.handler({
          params: {
            walletAddress: 'ldpos6312b77c6ca4233141835eb37f8f33a45f18d50f',
            fromTimestamp: 0,
            limit: 100
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 0);
      });

    });

    describe('getInboundTransactionsFromBlock action', async () => {

      it('should return an array of transactions sent to the specified walletAddress', async () => {
        let recipientAddress = 'ldpos5f0bc55450657f7fcb188e90122f7e4cee894199';
        let transactions = await chainModule.actions.getInboundTransactionsFromBlock.handler({
          params: {
            walletAddress: recipientAddress,
            blockId: blockList[0].id
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 1);
        let txn = transactions[0];

        assert.equal(typeof txn.id, 'string');
        assert.equal(typeof txn.message, 'string');
        assert.equal(typeof txn.amount, 'string');
        assert.equal(Number.isNaN(Number(txn.amount)), false);
        assert.equal(Number.isInteger(txn.timestamp), true);
        assert.equal(typeof txn.senderAddress, 'string');
        assert.equal(typeof txn.recipientAddress, 'string');

        assert.equal(transactions[0].recipientAddress, recipientAddress);
        assert.equal(transactions[0].message, '1');
      });

      it('should return an empty array if no transactions match the specified blockId', async () => {
        let recipientAddress = 'ldpos5f0bc55450657f7fcb188e90122f7e4cee894199';
        let transactions = await chainModule.actions.getInboundTransactionsFromBlock.handler({
          params: {
            walletAddress: recipientAddress,
            blockId: '31d9d53d4912be178c3bd5421a59b2a32f9560ca'
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 0);
      });

      it('should return an empty array if no transactions match the specified walletAddress', async () => {
        let recipientAddress = 'ldpos5f0bc55450657f7fcb188e90122f7e4cee894199';
        let transactions = await chainModule.actions.getInboundTransactionsFromBlock.handler({
          params: {
            walletAddress: 'ldpos6312b77c6ca4233141835eb37f8f33a45f18d50f',
            blockId: blockList[0].id
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 0);
      });

    });

    describe('getOutboundTransactionsFromBlock action', async () => {

      it('should return an array of transactions sent to the specified walletAddress', async () => {
        let transactions = await chainModule.actions.getOutboundTransactionsFromBlock.handler({
          params: {
            walletAddress: clientForger.walletAddress,
            blockId: blockList[0].id
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 2);

        for (let txn of transactions) {
          assert.equal(typeof txn.id, 'string');
          assert.equal(typeof txn.message, 'string');
          assert.equal(typeof txn.amount, 'string');
          assert.equal(Number.isNaN(Number(txn.amount)), false);
          assert.equal(Number.isInteger(txn.timestamp), true);
          assert.equal(typeof txn.senderAddress, 'string');
          assert.equal(typeof txn.recipientAddress, 'string');
        }

        assert.equal(transactions[0].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[0].message, '0');
        assert.equal(transactions[1].senderAddress, clientForger.walletAddress);
        assert.equal(transactions[1].message, '1');
      });

      it('should return transactions with a valid signatures property if transaction is from a multisig wallet', async () => {
        let transactions = await chainModule.actions.getOutboundTransactionsFromBlock.handler({
          params: {
            walletAddress: clientForger.walletAddress,
            blockId: blockList[2].id
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 1);
        let txn = transactions[0];

        assert.equal(typeof txn.id, 'string');
        assert.equal(typeof txn.message, 'string');
        assert.equal(typeof txn.amount, 'string');
        assert.equal(Number.isNaN(Number(txn.amount)), false);
        assert.equal(Number.isInteger(txn.timestamp), true);
        assert.equal(Array.isArray(txn.signatures), true);
        for (let signature of txn.signatures) {
          assert.notEqual(signature, null);
          assert.equal(typeof signature.signerAddress, 'string');
        }
        assert.equal(typeof txn.senderAddress, 'string');
        assert.equal(typeof txn.recipientAddress, 'string');
      });

      it('should return an empty array if no transactions match the specified blockId', async () => {
        let transactions = await chainModule.actions.getOutboundTransactionsFromBlock.handler({
          params: {
            walletAddress: clientForger.walletAddress,
            blockId: '31d9d53d4912be178c3bd5421a59b2a32f9560ca'
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 0);
      });

      it('should return an empty array if no transactions match the specified walletAddress', async () => {
        let transactions = await chainModule.actions.getOutboundTransactionsFromBlock.handler({
          params: {
            walletAddress: 'ldpos6312b77c6ca4233141835eb37f8f33a45f18d50f',
            blockId: blockList[0].id
          }
        });
        assert.equal(Array.isArray(transactions), true);
        assert.equal(transactions.length, 0);
      });

    });

    describe('getLastBlockAtTimestamp action', async () => {

      it('should return the highest block which is below the specified timestamp', async () => {
        let block = await chainModule.actions.getLastBlockAtTimestamp.handler({
          params: {
            timestamp: 31000
          }
        });
        assert.notEqual(block, null);
        assert.equal(block.height, 1);
      });

      it('should throw a BlockDidNotExistError error if no block can be found before the specified timestamp', async () => {
        let caughtError = null;
        try {
          await chainModule.actions.getLastBlockAtTimestamp.handler({
            params: {
              timestamp: 29000
            }
          });
        } catch (error) {
          caughtError = error;
        }
        assert.notEqual(caughtError, null);
        assert.equal(caughtError.type, 'InvalidActionError');
        assert.equal(caughtError.name, 'BlockDidNotExistError');
      });

    });

    describe('getMaxBlockHeight action', async () => {

      it('should return the height of the block as an integer number', async () => {
        let height = await chainModule.actions.getMaxBlockHeight.handler();
        assert.equal(height, 3);
      });

    });

    describe('getBlocksBetweenHeights action', async () => {

      it('should return blocks whose height is greater than fromHeight and less than or equal to toHeight', async () => {
        let blocks = await chainModule.actions.getBlocksBetweenHeights.handler({
          params: {
            fromHeight: 1,
            toHeight: 2,
            limit: 100
          }
        });
        assert.equal(Array.isArray(blocks), true);
        assert.equal(blocks.length, 1);
        let block = blocks[0];
        assert.equal(typeof block.id, 'string');
        assert.equal(Number.isInteger(block.timestamp), true);
        assert.equal(block.height, 2);
      });

      it('should return blocks whose height is greater than fromHeight and less than or equal to toHeight', async () => {
        let blocks = await chainModule.actions.getBlocksBetweenHeights.handler({
          params: {
            fromHeight: 0,
            toHeight: 2,
            limit: 1
          }
        });
        assert.equal(Array.isArray(blocks), true);
        assert.equal(blocks.length, 1);
        assert.equal(blocks[0].height, 1);
      });

      it('should return an empty array if no blocks are matched', async () => {
        let blocks = await chainModule.actions.getBlocksBetweenHeights.handler({
          params: {
            fromHeight: 9,
            toHeight: 10,
            limit: 10
          }
        });
        assert.equal(Array.isArray(blocks), true);
        assert.equal(blocks.length, 0);
      });

    });

    describe('getBlockAtHeight action', async () => {

      it('should expose a getBlockAtHeight action', async () => {
        let block = await chainModule.actions.getBlockAtHeight.handler({
          params: {
            height: 2
          }
        });
        assert.notEqual(block, null);
        assert.equal(block.height, 2);
        assert.equal(Number.isInteger(block.timestamp), true);
      });

      it('should throw a BlockDidNotExistError if no block could be matched', async () => {
        let caughtError = null;
        try {
          await chainModule.actions.getBlockAtHeight.handler({
            params: {
              height: 9
            }
          });
        } catch (error) {
          caughtError = error;
        }
        assert.notEqual(caughtError, null);
        assert.equal(caughtError.type, 'InvalidActionError');
        assert.equal(caughtError.name, 'BlockDidNotExistError');
      });

    });

    describe('postTransaction action', async () => {

      it('should accept a prepared (signed) transaction object as argument', async () => {
        // The format of the prepared (signed) transaction will be different depending on the
        // implementation of the chain module and the specified ChainCrypto adapter.
        // Since this is used for posting multisig transactions, the transaction will have
        // a 'signatures' property containing an array of signature objects created by the DEX.
        // The format of each signature object is flexible depending on the output of the ChainCrypto
        // adapter but it will have a 'signerAddress' property.
        // The chain module can handle the transaction and signature objects however it wants.
        let preparedTxn = await clientForger.prepareTransaction({
          type: 'transfer',
          recipientAddress: 'ldpos5f0bc55450657f7fcb188e90122f7e4cee894199',
          amount: '3300000000',
          fee: '100000000',
          timestamp: 100000,
          message: ''
        });
        await chainModule.actions.postTransaction.handler({
          params: {
            transaction: preparedTxn
          }
        });
      });

    });

  });

  describe('module events', async () => {

    beforeEach(async () => {
      options = {
        genesisPath: './test/utils/genesis-dex-api.json',
        forgingCredentials: [
          {
            forgingPassphrase: 'clerk aware give dog reopen peasant duty cheese tobacco trouble gold angle'
          }
        ],
        minTransactionsPerBlock: 0, // Enable forging empty blocks.
        forgingInterval: 10000,
        forgingBlockBroadcastDelay: 200,
        forgingSignatureBroadcastDelay: 200,
        propagationRandomness: 100,
        propagationTimeout: 5000
      };
      await launchChainModule(options);
    });

    it('should trigger bootstrap event after launch', async () => {
      await wait(200);
      assert.equal(bootstrapEventTriggered, true);
    });

    it('should expose a chainChanges event', async () => {
      await wait(13000);
      assert.equal(chainChangeEvents.length >=1, true);
      let eventData = chainChangeEvents[0].data;
      assert.equal(eventData.type, 'addBlock');
      let { block } = eventData;
      assert.notEqual(block, null);
      assert.equal(block.height, 1);
      assert.equal(Number.isInteger(block.timestamp), true);
    });

  });

});
