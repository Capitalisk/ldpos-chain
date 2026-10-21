const {
  validatePublicKey,
  validateKeyIndex,
  validateSignature,
  validateSignatureHash
} = require('./primitives');

function validateSigTransactionSchema(sigTransaction, fullCheck) {
  if (!sigTransaction) {
    throw new Error('Sig transaction was not specified');
  }
  if (sigTransaction.signatures != null) {
    throw new Error(
      `Sig transaction had a signatures property which is only allowed on multisig transactions`
    );
  }
  validatePublicKey('sigPublicKey', sigTransaction);
  validatePublicKey('nextSigPublicKey', sigTransaction);
  validateKeyIndex('nextSigKeyIndex', sigTransaction);
  if (fullCheck) {
    validateSignature('senderSignature', sigTransaction);
    if (sigTransaction.senderSignatureHash) {
      throw new Error(
        `Sig transaction had a senderSignatureHash property which is not allowed during a full check`
      );
    }
  } else {
    validateSignatureHash('senderSignatureHash', sigTransaction);
    if (sigTransaction.senderSignature) {
      throw new Error(
        `Sig transaction had a senderSignature property which is not allowed during a partial check`
      );
    }
  }
}

module.exports = {
  validateSigTransactionSchema
};
