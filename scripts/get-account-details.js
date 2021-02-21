// Utility script to generate account details to put in genesis.json

const bip39 = require('bip39');
const LiteMerkle = require('lite-merkle');
const mnemonic = process.argv[2];
const network = process.argv[3] || 'ldpos';

if (!mnemonic) {
  console.error('Passphrase mnemonic was not specified');
  process.exit(1);
}

const SEED_ENCODING = 'hex';
const NODE_ENCODING = 'hex';
const ADDRESS_ENCODING = 'hex';

let merkle = new LiteMerkle({
  leafCount: 64,
  seedEncoding: SEED_ENCODING,
  nodeEncoding: NODE_ENCODING
});

let seed = bip39.mnemonicToSeedSync(mnemonic).toString(SEED_ENCODING);

console.log('SEED:', seed);
console.log('');

let forgingTree = merkle.generateMSSTreeSync(seed, `${network}-forging-0`);
let multisigTree = merkle.generateMSSTreeSync(seed, `${network}-multisig-0`);
let sigTree = merkle.generateMSSTreeSync(seed, `${network}-sig-0`);

let walletAddress = `${network}${Buffer.from(sigTree.publicRootHash, NODE_ENCODING).slice(0, 20).toString(ADDRESS_ENCODING)}`;

console.log('------FORGING PUBLIC KEY------');
console.log(forgingTree.publicRootHash);
console.log('------MULTISIG PUBLIC KEY------');
console.log(multisigTree.publicRootHash);
console.log('------SIG PUBLIC KEY------');
console.log(sigTree.publicRootHash);

console.log('');

console.log('------WALLET ADDRESS------');
console.log(walletAddress);
