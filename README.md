# AWS KMS based Ethereum Tx Signing

This repo shows how to sign an Ethereum transaction using AWS KMS.

## Migration Updates

Migrated from legacy libraries to modern equivalents:

1. Replaced bn, web3, and ethereum-utils with ethers.js v6
2. Upgraded from AWS SDK v2 to AWS SDK v3
3. Switched from Kovan (Infura) to Sepolia (Alchemy) for Ethereum testnet services

Successful transaction: [View on Etherscan](https://sepolia.etherscan.io/tx/0xa5dcebd1abc37d76d072b6a8442f8a363569e217ab6069a576be96a5e74000d2)

## Medium

Please see my [medium article](https://luhenning.medium.com/the-dark-side-of-the-elliptic-curve-signing-ethereum-transactions-with-aws-kms-in-javascript-83610d9a6f81) for a detailed code walk-through.

## Prep

1. Create ECDSA secp256k1 key in AWS KMS
2. Create AWS IAM user with programmatic access to AWS KMS.
3. For the Tx to go through, you need to provide a valid web3 provider (e.g. Alchemy)
4. Run the script to generate the Ethereum address and fund the Ethereum account to pay for the transaction gas.
