const {
  validateWalletAddressValue,
  validateCount
} = require('./primitives');

function validateRegisterMultisigWalletTransactionSchema(transaction, minMultisigMembers, maxMultisigMembers, networkSymbol) {
  if (!transaction) {
    throw new Error('Register multisig transaction was not specified');
  }
  if (
    !Array.isArray(transaction.memberAddresses) ||
    transaction.memberAddresses.length < minMultisigMembers ||
    transaction.memberAddresses.length > maxMultisigMembers
  ) {
    throw new Error(
      `Register multisig transaction memberAddresses must be an array of length between ${
        minMultisigMembers
      } and ${
        maxMultisigMembers
      }`
    );
  }
  validateCount('requiredSignatureCount', transaction);
  let maxMembers = Math.min(transaction.memberAddresses.length, maxMultisigMembers);
  if (transaction.requiredSignatureCount < 1 || transaction.requiredSignatureCount > maxMembers) {
    throw new Error(
      `Register multisig transaction requiredSignatureCount must be between 1 and ${
        maxMembers
      }; it cannot exceed the number of member addresses`
    );
  }
  for (let memberAddress of transaction.memberAddresses) {
    try {
      validateWalletAddressValue(memberAddress, networkSymbol);
    } catch (error) {
      throw new Error(
        `Register multisig transaction memberAddresses must contain valid wallet addresses - ${
          error.message
        }`
      );
    }
  }

  return ['requiredSignatureCount', 'memberAddresses'];
}

module.exports = {
  validateRegisterMultisigWalletTransactionSchema
};
