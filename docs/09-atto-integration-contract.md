# Atto Integration Contract

> Canonical OWS integration note for Atto identifiers, account derivation,
> amount units, address format, network names, and transaction-signing scope.
> This is a pre-implementation contract: implementation tasks should follow the
> concrete rules below and treat items marked **Provisional** as follow-up
> questions for Atto/OpenWallet maintainers before publishing stable support.

## Status

Atto is a standalone layer-1 digital cash network. It is not an ERC-20 token,
not an EVM chain, and not a Nano fork. Atto shares some concepts with Nano
(account-chains, feeless transfers, ORV-style consensus), but OWS MUST NOT treat
Atto as Nano-compatible for identifiers, address derivation, block hashing,
signing, RPC transport, or transaction serialization.

## Chain identifiers

OWS uses CAIP-2 chain IDs and CAIP-10 account IDs in wallet files, policy
contexts, audit logs, and API parameters. No formal Chain Agnostic Namespace for
Atto was found in `chainagnostic/namespaces`, so the MVP should use a dedicated
Atto namespace and explicitly mark it provisional until Atto/OpenWallet upstream
confirm or register it.

| Atto network enum | OWS CAIP-2 chain ID | Status |
|---|---|---|
| `LIVE` | `atto:live` | **Provisional** canonical main network ID |
| `BETA` | `atto:beta` | **Provisional** |
| `DEV` | `atto:dev` | **Provisional** |
| `LOCAL` | `atto:local` | **Provisional**, local deployments only |
| `UNKNOWN` | none | MUST NOT be accepted as a persisted chain ID |

Rules:

- Persist only full CAIP-2 chain IDs such as `atto:live`; CLI aliases are
  convenience-only and MUST be resolved before wallet/policy/audit storage.
- CAIP-10 account IDs are `${chain_id}:${address}`. Example:
  `atto:live:atto://aaferyy3quqiyugpambc452bu2oqh7hrcazz4vnvem2meaa6thwf4vkiuiwyw`.
- The `atto` namespace satisfies CAIP-2 namespace syntax (`[-a-z0-9]{3,8}`) and
  the proposed references satisfy CAIP-2 reference syntax
  (`[-_a-zA-Z0-9]{1,32}`).
- Do not reuse `nano`, `xno`, `bip122`, `eip155`, or a generic `native` chain ID
  for Atto.

Follow-up question for Atto/OpenWallet: should Atto register a Chain Agnostic
Namespace profile with these references, or should OWS adopt a different
namespace/reference pair before stable release?

## HD derivation and coin type

The public SLIP-44 registry includes Atto:

```text
1869902945 | 0xef747461 | ATTO | Atto
```

Atto's own `attocash/commons` library uses the same coin type and derives
Ed25519 keys from the BIP-39 seed using this path shape:

```text
m/44'/1869902945'/{index}'
```

`1869902945` is the little-endian integer form of ASCII `atto`; its hardened
path component is `0xef747461`. OWS should use this as the canonical Atto
derivation path so accounts match the current Atto wallet/common library
behavior.

| Field | Value |
|---|---|
| Curve | Ed25519 |
| Signature algorithm | Standard Ed25519 over the Atto block hash |
| SLIP-44 coin type | `1869902945` (`0x6f747461`, little-endian ASCII `atto`) |
| Hardened path component | `0xef747461` |
| Account path | `m/44'/1869902945'/{index}'` |
| Account index | Hardened OWS account index, starting at `0'` |

Do not use Nano's SLIP-44 coin type (`165`) or Nano derivation/address rules.

Follow-up question for Atto/OpenWallet: confirm that OWS should expose only the
Atto Commons-compatible `m/44'/1869902945'/{index}'` account path and does not
need any legacy/non-standard derivation compatibility mode.

## Address format

Atto addresses are URI strings, not Nano addresses:

```text
^atto://[a-z2-7]{61}$
```

The 61-character lowercase base32 path decodes to 38 bytes:

1. 1 byte algorithm code (`0` for current `V1`)
2. 32-byte Ed25519 public key
3. 5-byte checksum

The checksum is BLAKE2b-5 over `algorithm_code || public_key`. The address is
encoded without padding and lowercased under the `atto://` scheme.

OWS account records should store both:

- `address`: the native Atto address URI (`atto://...`)
- `accountId`: the CAIP-10 identifier (`atto:live:atto://...`)

## Amount units and assets

Atto has 9 decimal places.

```text
1 ATTO = 1,000,000,000 raw units
```

Rules:

- Store and sign amounts as unsigned integer raw units.
- Do not use floating-point arithmetic for balances or transfer amounts.
- The native asset ID in OWS follows the existing native-asset convention:
  `atto:live:native`, `atto:beta:native`, etc.
- Atto transfers are feeless. There is no gas, fee, or fee-payer field in the
  Atto MVP signing model.

## MVP integration scope

OWS should implement Atto support as a local-key signing integration that can
construct, sign, and broadcast Atto transactions through infrastructure operated
by the integrator:

- historical node: account/receivable lookup and transaction publish/streaming
- work-server: lightweight anti-spam proof-of-work generation
- optional wallet-server: convenience only, not the canonical OWS signing path

The wallet-server can be useful for applications that want Atto-managed wallets,
account enable/disable flows, or simplified send/receive operations. However,
OWS's core value is local key custody and policy-gated signing, so MVP support
should not depend on wallet-server-managed private keys. Treat wallet-server
calls as an optional transport/convenience layer after the signer can build the
canonical block bytes itself.

## Transaction and block signing scope

Do not infer signing bytes from the OpenAPI JSON schema. The canonical signing
input is Atto's binary block serialization as implemented by `attocash/commons`,
then hashed with BLAKE2b-32. OWS signs that 32-byte block hash with standard
Ed25519.

Common binary field encodings:

- block type: `u8` (`OPEN=0`, `RECEIVE=1`, `SEND=2`, `CHANGE=3`)
- network: `u8` (`LIVE=0`, `BETA=1`, `DEV=2`, `LOCAL=3`)
- version: little-endian `u16` (`0` currently)
- algorithm: `u8` (`V1=0`, BLAKE2b + Ed25519)
- public keys and hashes: raw 32 bytes
- height: little-endian `u64`
- balance and amount: little-endian `u64` raw units
- timestamp: little-endian `i64` Unix epoch milliseconds

Canonical pre-signing block bytes by type:

### `SEND`

```text
type || network || version || algorithm || public_key || height || balance ||
timestamp || previous_hash || receiver_algorithm || receiver_public_key || amount
```

Size: 134 bytes.

### `RECEIVE`

```text
type || network || version || algorithm || public_key || height || balance ||
timestamp || previous_hash || send_hash_algorithm || send_hash
```

Size: 126 bytes.

### `OPEN`

```text
type || network || version || algorithm || public_key || balance || timestamp ||
send_hash_algorithm || send_hash || representative_algorithm ||
representative_public_key
```

Size: 119 bytes. Height is implicitly `1` and is not present in the serialized
open block bytes.

### `CHANGE`

```text
type || network || version || algorithm || public_key || height || balance ||
timestamp || previous_hash || representative_algorithm || representative_public_key
```

Size: 126 bytes.

After signing, an Atto transaction envelope carries:

```text
block || signature || work
```

where `signature` is 64 bytes and `work` is an 8-byte nonce generated for the
relevant Atto work target/network rules.

Implementation tasks MUST verify their serializer against Atto Commons test
vectors or generated fixture vectors before enabling real transaction signing.

## Open follow-up checklist

- Confirm or register the provisional CAIP namespace/references:
  `atto:live`, `atto:beta`, `atto:dev`, `atto:local`.
- Confirm that OWS should use only the SLIP-44/Atto Commons path
  `m/44'/1869902945'/{index}'` for new Atto accounts.
- Obtain or generate canonical Atto block/signature/work test vectors for all
  four block types.
- Decide whether wallet-server convenience calls belong in OWS core docs or in a
  separate integration guide after local signer support lands.

## Sources

- Atto integration docs: https://atto.cash/docs/integration
- Atto Node API: https://atto.cash/api/node
- Atto Wallet Server API: https://atto.cash/api/wallet
- Atto non-Nano-fork clarification: https://atto.cash/blog/is-atto-a-fork-of-nano
- Atto Commons serialization/signing implementation:
  https://github.com/attocash/commons
- CAIP-2: https://chainagnostic.org/CAIPs/caip-2
- CAIP namespaces registry: https://github.com/chainagnostic/namespaces
- SLIP-44 registry: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
