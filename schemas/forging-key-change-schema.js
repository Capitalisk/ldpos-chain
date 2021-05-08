const {
  validateWalletAddress,
  validateBlockId,
  validatePublicKey,
  validateKeyIndex
} = require('./primitives');

const { findInvalidProperty } = require('./find-invalid-property');

const validPropertyList = [
  'blockId',
  'forgerAddress',
  'forgingPublicKey',
  'nextForgingPublicKey',
  'nextForgingKeyIndex'
];

function validateForgingKeyChangeSchema(forgingKeyChange, networkSymbol) {
  if (!forgingKeyChange) {
    throw new Error(
      'Block signature was not specified'
    );
  }
  validateBlockId('blockId', forgingKeyChange);
  validateWalletAddress('forgerAddress', forgingKeyChange, networkSymbol);
  validatePublicKey('forgingPublicKey', forgingKeyChange);
  validatePublicKey('nextForgingPublicKey', forgingKeyChange);
  validateKeyIndex('nextForgingKeyIndex', forgingKeyChange);

  let invalidProperty = findInvalidProperty(forgingKeyChange, validPropertyList);
  if (invalidProperty) {
    throw new Error(
      `Block contained a forging key change object which had an invalid ${invalidProperty} property`
    );
  }
}

module.exports = {
  validateForgingKeyChangeSchema
};
