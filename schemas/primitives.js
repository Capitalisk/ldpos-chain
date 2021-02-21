const ADDRESS_BASE_LENGTH = 40;
const MAX_SIGNATURE_LENGTH = 22784;
const SIGNATURE_HASH_LENGTH = 44;
const PUBLIC_KEY_LENGTH = 64;
const ID_LENGTH = 40;

function isValidWalletAddress(walletAddress, networkSymbol) {
  if (typeof walletAddress !== 'string') {
    return false;
  }
  let walletAddressLength = ADDRESS_BASE_LENGTH + networkSymbol.length;
  if (walletAddress.length !== walletAddressLength) {
    return false;
  }
  let addressSymbol = walletAddress.slice(0, networkSymbol.length);
  return addressSymbol === networkSymbol;
}

function validateWalletAddressValue(walletAddress, networkSymbol) {
  if (networkSymbol == null) {
    throw new Error(
      'Failed to validate wallet address value because the network symbol could not be determined'
    );
  }
  if (!isValidWalletAddress(walletAddress, networkSymbol)) {
    let walletAddressLength = ADDRESS_BASE_LENGTH + networkSymbol.length;
    throw new Error(
      `Wallet address must be a string of ${
        walletAddressLength
      } characters starting with ${
        networkSymbol
      }`
    );
  }
}

function validateWalletAddress(propertyName, packet, networkSymbol) {
  if (networkSymbol == null) {
    throw new Error(
      'Failed to validate wallet address because the network symbol could not be determined'
    );
  }
  let walletAddress = packet[propertyName];
  if (!isValidWalletAddress(walletAddress, networkSymbol)) {
    let walletAddressLength = ADDRESS_BASE_LENGTH + networkSymbol.length;
    throw new Error(
      `Wallet address in ${
        propertyName
      } must be a string of ${
        walletAddressLength
      } characters starting with ${
        networkSymbol
      }`
    );
  }
}

function validatePublicKey(propertyName, packet) {
  let publicKey = packet[propertyName];
  if (typeof publicKey !== 'string') {
    throw new Error(`Public key in ${propertyName} must be a string`);
  }
  if (publicKey.length !== PUBLIC_KEY_LENGTH) {
    throw new Error(`Public key in ${propertyName} must have a length of ${PUBLIC_KEY_LENGTH} characters`);
  }
}

function validateOffset(propertyName, packet) {
  let offset = packet[propertyName];
  if (offset != null && (!Number.isInteger(offset) || offset < 0 || offset > Number.MAX_SAFE_INTEGER)) {
    throw new Error(
      `If specified, offset in ${
        propertyName
      } must be an integer number between 0 and ${
        Number.MAX_SAFE_INTEGER
      } inclusive`
    );
  }
}

function validateLimit(propertyName, packet, maxLimit) {
  if (maxLimit == null) {
    throw new Error(
      'Failed to validate limit because the max limit could not be determined'
    );
  }
  let limit = packet[propertyName];
  if (limit != null && (!Number.isInteger(limit) || limit < 0 || limit > maxLimit)) {
    throw new Error(
      `If specified, limit in ${
        propertyName
      } must be an integer number between 0 and ${
        maxLimit
      } inclusive`
    );
  }
}

function validateSortOrder(propertyName, packet) {
  let order = packet[propertyName];
  if (order != null && order !== 'asc' && order !== 'desc') {
    throw new Error(
      `If specified, the sort order in ${
        propertyName
      } must be either asc or desc`
    );
  }
}

function validateKeyIndex(propertyName, packet) {
  let keyIndex = packet[propertyName];
  if (!Number.isInteger(keyIndex) || keyIndex < 0 || keyIndex > Number.MAX_SAFE_INTEGER) {
    throw new Error(
      `Next forging key index in ${
        propertyName
      } must be an integer number between 0 and ${
        Number.MAX_SAFE_INTEGER
      } inclusive`
    );
  }
}

function validateCount(propertyName, packet) {
  let count = packet[propertyName];
  if (!Number.isInteger(count) || count < 0 || count > Number.MAX_SAFE_INTEGER) {
    throw new Error(
      `Count in ${
        propertyName
      } must be an integer number between 0 and ${
        Number.MAX_SAFE_INTEGER
      } inclusive`
    );
  }
}

function validateSignature(propertyName, packet) {
  let signature = packet[propertyName];
  if (typeof signature !== 'string') {
    throw new Error(`Signature in ${propertyName} must be a string`);
  }
  if (signature.length > MAX_SIGNATURE_LENGTH) {
    throw new Error(`Signature in ${propertyName} must have a length of no more than ${MAX_SIGNATURE_LENGTH} characters`);
  }
}

function validateSignatureHash(propertyName, packet) {
  let signatureHash = packet[propertyName];
  if (typeof signatureHash !== 'string') {
    throw new Error(`Signature hash in ${propertyName} must be a string`);
  }
  if (signatureHash.length !== SIGNATURE_HASH_LENGTH) {
    throw new Error(`Signature hash in ${propertyName} must have a length of ${SIGNATURE_HASH_LENGTH} characters`);
  }
}

function validateBlockId(propertyName, packet) {
  let blockId = packet[propertyName];
  if (typeof blockId !== 'string') {
    throw new Error(`Block ID must in ${propertyName} be a string`);
  }
  if (blockId.length !== ID_LENGTH) {
    throw new Error(`Block ID in ${propertyName} must have a length of ${ID_LENGTH} characters`);
  }
}

function validateBlockHeight(propertyName, packet) {
  let height = packet[propertyName];
  if (!Number.isInteger(height) || height < 0) {
    throw new Error(`Block height in ${propertyName} must be a positive integer number`);
  }
}

function validateTransactionId(propertyName, packet) {
  let transactionId = packet[propertyName];
  if (typeof transactionId !== 'string') {
    throw new Error(`Transaction ID in ${propertyName} must be a string`);
  }
  if (transactionId.length !== ID_LENGTH) {
    throw new Error(`Transaction ID in ${propertyName} must have a length of ${ID_LENGTH} characters`);
  }
}

function validateTransactionMessage(propertyName, packet, maxTransactionMessageLength) {
  let message = packet[propertyName];
  if (typeof message !== 'string') {
    throw new Error(`Transaction message in ${propertyName} must be a string`);
  }
  if (message.length > maxTransactionMessageLength) {
    throw new Error(
      `Transaction message in ${propertyName} must not exceed ${maxTransactionMessageLength} characters`
    );
  }
}

function validateTransactionAmount(propertyName, packet, maxSpendableDigits) {
  let amount = packet[propertyName];
  if (typeof amount !== 'string') {
    throw new Error(`Transaction amount in ${propertyName} must be a string`);
  }
  if (amount.length > maxSpendableDigits) {
    throw new Error(`Transaction amount in ${propertyName} exceeded the maximum spendable digits`);
  }
  if (BigInt(amount).toString() !== amount) {
    throw new Error(`Transaction amount in ${propertyName} was not serializable`);
  }
}

function validateTransactionFee(propertyName, packet, maxSpendableDigits) {
  let fee = packet[propertyName];
  if (typeof fee !== 'string') {
    throw new Error(`Transaction fee in ${propertyName} must be a string`);
  }
  if (fee.length > maxSpendableDigits) {
    throw new Error(`Transaction fee in ${propertyName} exceeded the maximum spendable digits`);
  }
  if (BigInt(fee).toString() !== fee) {
    throw new Error(`Transaction fee in ${propertyName} was not serializable`);
  }
}

function validateTimestamp(propertyName, packet) {
  let timestamp = packet[propertyName];
  if (!Number.isInteger(timestamp) || timestamp < 0) {
    throw new Error(`Timestamp in ${propertyName} must be a positive integer number`);
  }
}

module.exports = {
  validateWalletAddress,
  validateWalletAddressValue,
  validatePublicKey,
  validateKeyIndex,
  validateCount,
  validateSignature,
  validateSignatureHash,
  validateBlockId,
  validateBlockHeight,
  validateTransactionId,
  validateTransactionMessage,
  validateTransactionAmount,
  validateTransactionFee,
  validateOffset,
  validateLimit,
  validateSortOrder,
  validateTimestamp,
  ADDRESS_BASE_LENGTH,
  ID_LENGTH,
  MAX_SIGNATURE_LENGTH,
  SIGNATURE_HASH_LENGTH,
  PUBLIC_KEY_LENGTH
};
