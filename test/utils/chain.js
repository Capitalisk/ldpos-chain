class LDPoSChainModule {
  constructor() {
    this.receivedBlockIdSet = new Set();
    this.receivedBlockList = [];
    this.receivedTransactionIdSet = new Set();
    this.receivedBlockSignatureSet = new Set();
    this.receivedBlockTrailerSignatureSet = new Set();
  }

  setNetwork(network) {
    this.network = network;
  }

  get eventHandlers() {
    return {
      block: async (block) => {
        if (block && block.id && !this.receivedBlockIdSet.has(block.id)) {
          this.receivedBlockIdSet.add(block.id);
          this.receivedBlockList[block.height - 1] = block;
          this.network.trigger('ldpos_chain', 'block', block);
        }
      },
      blockSignature: async (blockSignature) => {
        if (
          blockSignature &&
          blockSignature.signerAddress &&
          blockSignature.blockId &&
          !this.receivedBlockSignatureSet.has(`${blockSignature.blockId}.${blockSignature.signerAddress}`)
        ) {
          this.receivedBlockSignatureSet.add(`${blockSignature.blockId}.${blockSignature.signerAddress}`);
          this.network.trigger('ldpos_chain', 'blockSignature', blockSignature);
        }
      },
      blockTrailerSignature: async (blockTrailerSignature) => {
        if (
          blockTrailerSignature &&
          blockTrailerSignature.signerAddress &&
          blockTrailerSignature.blockId &&
          !this.receivedBlockTrailerSignatureSet.has(`${blockTrailerSignature.blockId}.${blockTrailerSignature.signerAddress}`)
        ) {
          this.receivedBlockTrailerSignatureSet.add(`${blockTrailerSignature.blockId}.${blockTrailerSignature.signerAddress}`);
          this.network.trigger('ldpos_chain', 'blockTrailerSignature', blockTrailerSignature);
        }
      },
      transaction: async (transaction) => {
        if (transaction && transaction.id && !this.receivedTransactionIdSet.has(transaction.id)) {
          this.receivedTransactionIdSet.add(transaction.id);
          this.network.trigger('ldpos_chain', 'transaction', transaction);
        }
      }
    }
  }

  get actionHandlers() {
    return {
      getSignedBlocksFromHeight: async ({ height, limit }) => {
        let startIndex = height - 1;
        return this.receivedBlockList.slice(startIndex, startIndex + limit);
      }
    };
  }
}

module.exports = LDPoSChainModule;
