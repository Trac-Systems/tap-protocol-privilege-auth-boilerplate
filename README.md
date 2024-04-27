# Privilege Authority Boilerplate for TAP Protocol

This boilerplate generates inscription texts to create privilege authorities as well as signed mint, dmt-mint and general purpose verifaction inscriptions (see https://github.com/Trac-Systems/tap-protocol-specs).

A privilege authority enables sub-indexers to hook into the TAP Protocol and allows for specifying which address is allowed to mint (or owning the provenance as of general purpose verifications).

Projects may find this boilerplate useful to implement whitelists, launchpads, burn-bridges for tokens, dmt-tokens, unats and cross-chain assets.

What it does:

- Demonstrates how to create a privilege authority.
- Demonstrates how a privilege authority generates and signs mint, dmt-mint and verification inscriptions.

## Requirements

NodeJS 20+

## Installation & Execution

Clone this repository in order to run:

```
git clone https://github.com/Trac-Systems//tap-protocol-privilege-auth-boilerplate.git
cd /tap-protocol-privilege-auth-boilerplate
npm i
node token-auth.mjs
```
