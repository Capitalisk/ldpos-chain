// Utility script to generate account details to put in genesis.json

const bip39 = require('bip39');
const childProcess = require('child_process');
const { fork } = childProcess;
const path = require('path');
const LiteMerkle = require('lite-merkle');

const network = process.argv[2] || 'ldpos';

let merkle = new LiteMerkle({
  leafCount: 64
});

let mnemonic = bip39.generateMnemonic();

console.log('MNEMONIC:', mnemonic);

fork(path.resolve(__dirname, './get-account-details.js'), [mnemonic, network]);
