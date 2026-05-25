# Atto RPC fixtures

Provenance:
- Shapes are based on `ows/crates/ows-lib/src/atto_rpc.rs`, `docs/09-atto-integration-contract.md`, and the Atto Node/work-server API references linked from that contract.
- Fixtures are synthetic and network-free. They exercise OWS parsing, request serialization, publish success/failure handling, and work-server success/failure handling without depending on live Atto infrastructure.
- Live Atto smoke coverage is opt-in only: run the ignored test with `ATTO_NODE_URL` set, e.g. `cargo test -p ows-lib --test atto_rpc_fixtures -- --ignored live_node_time_difference_smoke_requires_env`. Optional: `ATTO_CLIENT_INSTANT=<millis>`.

No private endpoints or secrets are required for the default fixture tests.
