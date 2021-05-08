const {
  validateWalletAddress,
  validateKeyIndex,
  validateCount,
  validateBlockId,
  validatePublicKey,
  validateTimestamp,
  validateBlockHeight,
  validateSignature
} = require('./primitives');

const { validateBlockSignatureSchema } = require('./block-signature-schema');
const { validateForgingKeyChangeSchema } = require('./forging-key-change-schema');
const { findInvalidProperty } = require('./find-invalid-property');

const validPropertyList = [
  'id',
  'height',
  'timestamp',
  'previousBlockId',
  'numberOfTransactions',
  'transactions',
  'forgerAddress',
  'forgingPublicKey',
  'nextForgingPublicKey',
  'nextForgingKeyIndex',
  'forgerSignature',
  'forgingKeyChanges',
  'signatures'
];

function validateBlockSchema(block, minTransactionsPerBlock, maxTransactionsPerBlock, minSignatures, maxSignatures, maxForgingKeyChanges, networkSymbol) {
  if (!block) {
    throw new Error('Block was not specified');
  }
  validateBlockHeight('height', block);
  validateTimestamp('timestamp', block);
  if (block.previousBlockId != null) {
    validateBlockId('previousBlockId', block);
  }
  if (!Array.isArray(block.transactions)) {
    throw new Error('Block transactions must be an array');
  }
  if (block.transactions.length < minTransactionsPerBlock) {
    throw new Error(
      `Block did not contain enough transactions - Minimum allowed is ${minTransactionsPerBlock}`
    );
  }
  if (block.transactions.length > maxTransactionsPerBlock) {
    throw new Error(
      `Block contained too many transactions - Maximum allowed is ${maxTransactionsPerBlock}`
    );
  }
  validateCount('numberOfTransactions', block);
  if (block.numberOfTransactions !== block.transactions.length) {
    throw new Error(
      `Block number of transactions count did not match the number of transactions in the block - Expected ${
        block.transactions.length
      }`
    );
  }
  validateWalletAddress('forgerAddress', block, networkSymbol);
  validateBlockId('id', block);
  validatePublicKey('forgingPublicKey', block);
  validatePublicKey('nextForgingPublicKey', block);
  validateKeyIndex('nextForgingKeyIndex', block);
  validateSignature('forgerSignature', block);

  if (!Array.isArray(block.signatures)) {
    throw new Error('Block signatures must be an array');
  }
  if (block.signatures.length > maxSignatures) {
    throw new Error(
      `Block contained more than the maximum number of ${maxSignatures} signatures`
    );
  }

  if (!Array.isArray(block.forgingKeyChanges)) {
    throw new Error('Block forgingKeyChanges must be an array');
  }
  if (block.forgingKeyChanges.length > maxForgingKeyChanges) {
    throw new Error(
      `Block contained more than the maximum number of ${maxForgingKeyChanges} forgingKeyChanges`
    );
  }

  let invalidProperty = findInvalidProperty(block, validPropertyList);

  if (invalidProperty) {
    throw new Error(
      `Block had an invalid ${invalidProperty} property`
    );
  }

  let signerSet = new Set();
  for (let blockSignature of block.signatures) {
    validateBlockSignatureSchema(blockSignature, networkSymbol);
    if (blockSignature.signerAddress === block.forgerAddress) {
      throw new Error(
        `Block contained a second signature from the block forger ${block.forgerAddress}`
      );
    }
    if (signerSet.has(blockSignature.signerAddress)) {
      throw new Error(
        `Block contained duplicate signatures`
      );
    }
    signerSet.add(blockSignature.signerAddress);
  }
  if (signerSet.size < minSignatures) {
    throw new Error(
      `Block signatures did not refer to a sufficient number of unique signers - There were ${
        signerSet.size
      } signatures but ${minSignatures} were required`
    );
  }

  let forgerAddressSet = new Set();
  for (let keyChange of block.forgingKeyChanges) {
    validateForgingKeyChangeSchema(keyChange, networkSymbol);
    if (forgerAddressSet.has(keyChange.forgerAddress)) {
      throw new Error(
        `Block contained duplicate forgingKeyChanges`
      );
    }
    forgerAddressSet.add(keyChange.forgerAddress);
  }
}

module.exports = {
  validateBlockSchema
};
