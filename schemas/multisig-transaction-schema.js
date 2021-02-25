const {
  validateWalletAddress,
  validateSignature,
  validateSignatureHash,
  validatePublicKey,
  validateKeyIndex
} = require('./primitives');

const { findInvalidProperty } = require('./find-invalid-property');

const validSignaturePropertyList = [
  'signerAddress',
  'multisigPublicKey',
  'nextMultisigPublicKey',
  'nextMultisigKeyIndex',
  'signature',
  'signatureHash'
];

function validateMultisigTransactionSchema(multisigTransaction, minSignatures, maxSignatures, networkSymbol, fullCheck) {
  if (!multisigTransaction) {
    throw new Error('Multisig transaction was not specified');
  }
  let { signatures } = multisigTransaction;
  if (!Array.isArray(signatures)) {
    throw new Error('Multisig transaction signatures must be an array');
  }
  if (signatures.length > maxSignatures) {
    throw new Error(
      `Multisig transaction contained more than the maximum number of ${maxSignatures} signatures`
    );
  }
  let processedSignerAddressSet = new Set();
  for (let signaturePacket of signatures) {
    if (!signaturePacket) {
      throw new Error('Some multisig transaction signatures were not specified');
    }
    let {
      signerAddress,
      signature,
      signatureHash
    } = signaturePacket;

    validateWalletAddress('signerAddress', signaturePacket, networkSymbol);

    validatePublicKey('multisigPublicKey', signaturePacket);
    validatePublicKey('nextMultisigPublicKey', signaturePacket);
    validateKeyIndex('nextMultisigKeyIndex', signaturePacket);

    if (fullCheck) {
      validateSignature('signature', signaturePacket);
      if (signatureHash) {
        throw new Error(
          `Multisig transaction contained a signature object with a signatureHash property which is not allowed during a full check`
        );
      }
    } else {
      validateSignatureHash('signatureHash', signaturePacket);
      if (signature) {
        throw new Error(
          `Multisig transaction contained a signature object with a signature property which is not allowed during a partial check`
        );
      }
    }

    let invalidProperty = findInvalidProperty(signaturePacket, validSignaturePropertyList);

    if (invalidProperty) {
      throw new Error(
        `Multisig transaction contained a signature object with an invalid ${
          invalidProperty
        } property`
      );
    }

    if (processedSignerAddressSet.has(signerAddress)) {
      throw new Error(
        `Multiple multisig transaction signatures were associated with the same member address ${
          signerAddress
        }`
      );
    }
    processedSignerAddressSet.add(signerAddress);
  }
  if (processedSignerAddressSet.size < minSignatures) {
    throw new Error(
      `Multisig transaction did not have enough member signatures - At least ${
        minSignatures
      } distinct signatures are required`
    );
  }
}

module.exports = {
  validateMultisigTransactionSchema
};
