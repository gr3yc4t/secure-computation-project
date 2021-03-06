# Secure Computation Project
Implementation of a smart contract responsible for keeping track of redactable blockchain modification

## Requirements
* Solidity Compiler
* Zokrates

Alternatively you could use the [Remix IDE](https://remix.ethereum.org/) with the [Zokreates](https://github.com/zokrates/zokrates) plugin.

## Building
* Compile `locally_redactable_nizk.zok` with Zokrates and generate `verifier.sol`
* Compile `KeyManagementOracle.sol` with a Solidity compiler (e.g. [solc](https://github.com/ethereum/solidity))

## Usage
The contract must be initialized with the scheme parameter `k` and a commitment to the trapdoor key.
The Pedersen commitment requires two point `G, H` that can be generated using the script inside `commitment_generation`.

When the method `FinalizeCollision` is called, the parameters `a`, `b` and `c` represent the zk-SNARKs proof generated by Zokrates. Instead, `c0` and `c1` represent the i-th collision key of the scheme divided in two `field` element. See [how](https://zokrates.github.io/sha256example.html) `sha256packed` works in Zokrates for better understanding.
