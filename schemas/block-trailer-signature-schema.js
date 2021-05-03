const {
  validateSignature,
  validateWalletAddress,
  validateWalletAddressValue,
  validateBlockId,
  validateKeyIndex,
  validatePublicKey
} = require('./primitives');

const { findInvalidProperty } = require('./find-invalid-property');

const validPropertyList = [
  'blockId',
  'blockSignerAddresses',
  'signerAddress',
  'forgingPublicKey',
  'nextForgingPublicKey',
  'nextForgingKeyIndex',
  'signature'
];

function validateBlockTrailerSignatureSchema(blockTrailerSignature, maxAddresses, networkSymbol) {
  if (!blockTrailerSignature) {
    throw new Error(
      'Block signature was not specified'
    );
  }
  validateBlockId('blockId', blockTrailerSignature);
  validateWalletAddress('signerAddress', blockTrailerSignature, networkSymbol);
  validatePublicKey('forgingPublicKey', blockTrailerSignature);
  validatePublicKey('nextForgingPublicKey', blockTrailerSignature);
  validateKeyIndex('nextForgingKeyIndex', blockTrailerSignature);
  validateSignature('signature', blockTrailerSignature);

  let blockSignerAddresses = blockTrailerSignature.blockSignerAddresses;
  if (!Array.isArray(blockSignerAddresses)) {
    throw new Error('Block blockSignerAddresses must be an array');
  }

  if (blockSignerAddresses.length > maxAddresses) {
    throw new Error(
      `Block blockSignerAddresses array contained more than the maximum number of ${
        maxAddresses
      } addresses`
    );
  }

  for (let blockSignerAddress of blockSignerAddresses) {
    try {
      validateWalletAddressValue(blockSignerAddress, networkSymbol);
    } catch (error) {
      throw new Error(
        `Block blockSignerAddresses must contain valid wallet addresses - ${
          error.message
        }`
      );
    }
  }

  let invalidProperty = findInvalidProperty(blockTrailerSignature, validPropertyList);
  if (invalidProperty) {
    throw new Error(
      `Block contained a signature which had an invalid ${invalidProperty} property`
    );
  }
}

module.exports = {
  validateBlockTrailerSignatureSchema
};
