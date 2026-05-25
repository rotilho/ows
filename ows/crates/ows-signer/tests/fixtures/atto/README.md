# Atto signer fixtures

Provenance:
- Address envelope/codec rules are from `docs/09-atto-integration-contract.md` and the linked Atto sources there: Atto integration docs, Node API, and Atto Commons.
- Mnemonic-derived key/address/signature vectors in `signer_vectors.json` were generated locally from the current OWS Atto implementation on this branch using BIP-39 mnemonic `abandon ... about`, empty passphrase, Ed25519, and Atto path `m/44'/1869902945'/{index}'`. They are regression fixtures until Atto/OpenWallet publish official vectors.
- Block hash/signature cases sign fixed 32-byte placeholder hashes for SEND/RECEIVE/OPEN/CHANGE. They validate Ed25519 signing over the canonical block hash input, not canonical Atto block serialization. Official Atto Commons block serialization vectors are still missing; see `docs/09-atto-integration-contract.md` open checklist.

Do not put secrets here. The mnemonic is the public BIP-39 test mnemonic.
