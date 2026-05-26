//! Atto Node and work-server REST helpers.
//!
//! Uses `curl` for HTTP, consistent with the rest of `ows-lib` (no added HTTP
//! runtime dependency). Amounts/heights are modeled as decimal strings so raw
//! Atto units are never converted through floating point.
//!
//! API sources:
//! - Node OpenAPI: <https://atto.cash/api/node>
//! - Work-server remote contract: Atto Commons `commons-worker-remote`, which
//!   posts `AttoWorkerOperations.Request` to `POST /works` and expects
//!   `{ "work": "<16 hex chars>" }`.

use crate::error::OwsLibError;
use serde::{
    de::{self, Visitor},
    Deserialize, Serialize,
};
use serde_json::Value;
use std::process::Command;

pub type AttoAddress = String;
pub type AttoPublicKey = String;
pub type AttoHash = String;
pub type AttoAmount = String;
pub type AttoHeight = String;
pub type AttoInstant = i64;
pub type AttoSignature = String;
pub type AttoWork = String;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttoAccount {
    #[serde(rename = "publicKey")]
    pub public_key: AttoPublicKey,
    pub network: String,
    pub version: u32,
    pub algorithm: String,
    #[serde(deserialize_with = "u64_decimal_string")]
    pub height: AttoHeight,
    #[serde(deserialize_with = "u64_decimal_string")]
    pub balance: AttoAmount,
    #[serde(rename = "lastTransactionHash")]
    pub last_transaction_hash: AttoHash,
    #[serde(rename = "lastTransactionTimestamp")]
    pub last_transaction_timestamp: AttoInstant,
    #[serde(rename = "representativeAlgorithm")]
    pub representative_algorithm: String,
    #[serde(rename = "representativePublicKey")]
    pub representative_public_key: AttoPublicKey,
    #[serde(rename = "representativeAddress", default)]
    pub representative_address: AttoAddress,
    #[serde(default)]
    pub address: AttoAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttoReceivable {
    pub network: String,
    pub hash: AttoHash,
    pub version: u32,
    pub algorithm: String,
    #[serde(rename = "publicKey")]
    pub public_key: AttoPublicKey,
    pub timestamp: AttoInstant,
    #[serde(rename = "receiverAlgorithm")]
    pub receiver_algorithm: String,
    #[serde(rename = "receiverPublicKey")]
    pub receiver_public_key: AttoPublicKey,
    #[serde(deserialize_with = "u64_decimal_string")]
    pub amount: AttoAmount,
    #[serde(rename = "receiverAddress", default)]
    pub receiver_address: AttoAddress,
    #[serde(default)]
    pub address: AttoAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttoTransaction {
    /// Atto block payload. The node OpenAPI uses a discriminator across send,
    /// receive, open, and change block shapes; callers that construct/sign the
    /// block can pass the exact JSON shape here without lossy conversion.
    pub block: Value,
    pub signature: AttoSignature,
    pub work: AttoWork,
    pub address: AttoAddress,
}

impl AttoTransaction {
    /// Best-effort hash extraction from returned node payloads. Current node
    /// publish endpoints return either empty content (`POST /transactions`) or
    /// a streamed transaction (`POST /transactions/stream`); if a future node
    /// includes a hash in the block envelope this surfaces it to callers.
    pub fn returned_hash(&self) -> Option<&str> {
        self.block
            .get("hash")
            .and_then(Value::as_str)
            .or_else(|| self.block.get("transactionHash").and_then(Value::as_str))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeDifferenceResponse {
    #[serde(rename = "clientInstant", deserialize_with = "instant_string_or_ms")]
    pub client_instant: AttoInstant,
    #[serde(rename = "serverInstant", deserialize_with = "instant_string_or_ms")]
    pub server_instant: AttoInstant,
    #[serde(rename = "differenceMillis")]
    pub difference_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttoPublishResponse {
    pub status: AttoPublishStatus,
    pub hash: Option<AttoHash>,
    pub transaction: Option<AttoTransaction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttoPublishStatus {
    Published,
    PublishedAndStreamed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttoWorkRequest {
    pub network: String,
    pub timestamp: AttoInstant,
    /// Hex-encoded work target from Atto Commons `AttoWorkTarget.value.toHex()`.
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttoWorkResponse {
    pub work: AttoWork,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct AccountSearch<'a> {
    addresses: &'a [AttoAddress],
}

pub struct AttoNodeClient {
    base_url: String,
}

impl AttoNodeClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: trim_base_url(base_url.into()),
        }
    }

    /// `POST /accounts` for one address. Returns `Ok(None)` when the node
    /// returns an empty collection or 404 for an unopened/unknown account.
    pub fn account_by_address(&self, address: &str) -> Result<Option<AttoAccount>, OwsLibError> {
        let accounts = self.accounts_by_addresses(&[address.to_string()])?;
        Ok(accounts.into_iter().next())
    }

    /// `POST /accounts` for one or more addresses.
    pub fn accounts_by_addresses(
        &self,
        addresses: &[AttoAddress],
    ) -> Result<Vec<AttoAccount>, OwsLibError> {
        let body = serde_json::to_value(AccountSearch { addresses })?;
        let value = self.request_json("POST", "accounts", Some(&body), "application/json")?;
        parse_one_or_many(value, "accounts")
    }

    /// `GET /accounts/{publicKey}`. Returns `Ok(None)` for 404.
    pub fn account_by_public_key(
        &self,
        public_key: &str,
    ) -> Result<Option<AttoAccount>, OwsLibError> {
        match self.request_json(
            "GET",
            &format!("accounts/{public_key}"),
            None,
            "application/json",
        ) {
            Ok(value) => Ok(Some(serde_json::from_value(value)?)),
            Err(OwsLibError::BroadcastFailed(msg)) if msg.contains("HTTP 404") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Collect the NDJSON receivable stream for a public key into a vector.
    /// This is suitable for receive/open transaction construction, while the
    /// lower-level `receivable_stream_by_public_key` keeps the stream shape
    /// explicit for callers that want to handle long-lived responses themselves.
    pub fn list_receivables_by_public_key(
        &self,
        public_key: &str,
        min_amount: Option<&str>,
    ) -> Result<Vec<AttoReceivable>, OwsLibError> {
        self.receivable_stream_by_public_key(public_key, min_amount)
    }

    /// `GET /accounts/{publicKey}/receivables/stream` as collected NDJSON.
    pub fn receivable_stream_by_public_key(
        &self,
        public_key: &str,
        min_amount: Option<&str>,
    ) -> Result<Vec<AttoReceivable>, OwsLibError> {
        let path = with_min_amount(
            &format!("accounts/{public_key}/receivables/stream"),
            min_amount,
        );
        let body = self.request_text("GET", &path, None, "application/x-ndjson")?;
        parse_ndjson(&body)
    }

    /// `POST /accounts/receivables/stream` for multiple account addresses.
    pub fn receivable_stream_by_addresses(
        &self,
        addresses: &[AttoAddress],
        min_amount: Option<&str>,
    ) -> Result<Vec<AttoReceivable>, OwsLibError> {
        let path = with_min_amount("accounts/receivables/stream", min_amount);
        let body = serde_json::to_value(AccountSearch { addresses })?;
        let text = self.request_text("POST", &path, Some(&body), "application/x-ndjson")?;
        parse_ndjson(&text)
    }

    /// `GET /instants/{clientInstant}`. Atto Commons sends the millisecond
    /// epoch instant as the path segment; the node OpenAPI calls this
    /// `clientInstant` and uses it to return server/client clock skew.
    pub fn time_difference(
        &self,
        client_instant: AttoInstant,
    ) -> Result<TimeDifferenceResponse, OwsLibError> {
        let value = self.request_json(
            "GET",
            &format!("instants/{client_instant}"),
            None,
            "application/json",
        )?;
        Ok(serde_json::from_value(value)?)
    }

    /// `POST /transactions`, which the node documents as a successful empty
    /// response. Use `publish_transaction_and_stream` when a streamed returned
    /// transaction is needed.
    pub fn publish_transaction(
        &self,
        transaction: &AttoTransaction,
    ) -> Result<AttoPublishResponse, OwsLibError> {
        let body = serde_json::to_value(transaction)?;
        self.publish_transaction_value(&body)
    }

    /// `POST /transactions` with a caller-provided Atto node transaction JSON
    /// shape. This is used by the local signer path, which converts canonical
    /// signed Atto bytes into the flat JSON body expected by the node OpenAPI.
    pub fn publish_transaction_value(
        &self,
        transaction: &Value,
    ) -> Result<AttoPublishResponse, OwsLibError> {
        let _ = self.request_text(
            "POST",
            "transactions",
            Some(transaction),
            "application/json",
        )?;
        Ok(AttoPublishResponse {
            status: AttoPublishStatus::Published,
            hash: transaction
                .get("hash")
                .and_then(Value::as_str)
                .map(str::to_string),
            transaction: None,
        })
    }

    /// `POST /transactions/stream`, collected until the first streamed
    /// transaction. This returns a status plus the node-returned transaction;
    /// `hash` is best-effort because the current OpenAPI transaction schema has
    /// no top-level hash field.
    pub fn publish_transaction_and_stream(
        &self,
        transaction: &AttoTransaction,
    ) -> Result<AttoPublishResponse, OwsLibError> {
        let body = serde_json::to_value(transaction)?;
        let text = self.request_text(
            "POST",
            "transactions/stream",
            Some(&body),
            "application/x-ndjson",
        )?;
        let mut transactions: Vec<AttoTransaction> = parse_ndjson(&text)?;
        let transaction = transactions.drain(..).next().ok_or_else(|| {
            OwsLibError::BroadcastFailed("Atto transaction stream returned no transaction".into())
        })?;
        let hash = transaction.returned_hash().map(str::to_string);
        Ok(AttoPublishResponse {
            status: AttoPublishStatus::PublishedAndStreamed,
            hash,
            transaction: Some(transaction),
        })
    }

    fn request_json(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        accept: &str,
    ) -> Result<Value, OwsLibError> {
        let text = self.request_text(method, path, body, accept)?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text)?)
    }

    fn request_text(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        accept: &str,
    ) -> Result<String, OwsLibError> {
        http_call(method, &self.url(path), body, accept)
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }
}

pub struct AttoWorkServerClient {
    base_url: String,
}

impl AttoWorkServerClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: trim_base_url(base_url.into()),
        }
    }

    /// Atto Commons remote worker contract: `POST /works` with
    /// `{ network, timestamp, target }` and response `{ work }`.
    pub fn work(&self, request: &AttoWorkRequest) -> Result<AttoWorkResponse, OwsLibError> {
        let body = serde_json::to_value(request)?;
        let text = http_call(
            "POST",
            &format!("{}/works", self.base_url),
            Some(&body),
            "application/json",
        )?;
        Ok(serde_json::from_str(&text)?)
    }
}

fn trim_base_url(mut base_url: String) -> String {
    while base_url.ends_with('/') {
        base_url.pop();
    }
    base_url
}

fn with_min_amount(path: &str, min_amount: Option<&str>) -> String {
    match min_amount {
        Some(min_amount) => format!("{path}?minAmount={min_amount}"),
        None => path.to_string(),
    }
}

fn u64_decimal_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct U64DecimalStringVisitor;

    impl Visitor<'_> for U64DecimalStringVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an unsigned 64-bit integer as a JSON number or decimal string")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value.to_string())
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            u64::try_from(value)
                .map(|value| value.to_string())
                .map_err(|_| E::custom(format!("value {value} is not a valid u64")))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            value
                .parse::<u64>()
                .map(|parsed| parsed.to_string())
                .map_err(|_| E::custom(format!("value `{value}` is not a valid u64")))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&value)
        }
    }

    deserializer.deserialize_any(U64DecimalStringVisitor)
}

fn instant_string_or_ms<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Number(n) => n
            .as_i64()
            .ok_or_else(|| serde::de::Error::custom("instant number was not an i64")),
        Value::String(s) => chrono::DateTime::parse_from_rfc3339(&s)
            .map(|dt| dt.timestamp_millis())
            .map_err(serde::de::Error::custom),
        other => Err(serde::de::Error::custom(format!(
            "expected RFC3339 string or millisecond number, got {other}"
        ))),
    }
}

fn parse_one_or_many<T>(value: Value, label: &str) -> Result<Vec<T>, OwsLibError>
where
    T: for<'de> Deserialize<'de>,
{
    match value {
        Value::Array(_) => Ok(serde_json::from_value(value)?),
        Value::Null => Ok(Vec::new()),
        other if other.is_object() => Ok(vec![serde_json::from_value(other)?]),
        other => Err(OwsLibError::BroadcastFailed(format!(
            "Atto {label} response had unexpected JSON shape: {other}"
        ))),
    }
}

fn parse_ndjson<T>(body: &str) -> Result<Vec<T>, OwsLibError>
where
    T: for<'de> Deserialize<'de>,
{
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(OwsLibError::from))
        .collect()
}

fn http_call(
    method: &str,
    url: &str,
    body: Option<&Value>,
    accept: &str,
) -> Result<String, OwsLibError> {
    let is_ndjson_stream = accept == "application/x-ndjson";
    let mut args = vec![
        "-sS".to_string(),
        "-X".to_string(),
        method.to_string(),
        "-H".to_string(),
        "Content-Type: application/json".to_string(),
        "-H".to_string(),
        format!("Accept: {accept}"),
    ];

    // Atto stream endpoints are long-lived: they emit NDJSON records and keep
    // the HTTP connection open for future updates. OWS wallet operations need a
    // snapshot of currently available records, not an infinite subscription, so
    // bound the curl read and parse any complete lines received before timeout.
    if is_ndjson_stream {
        args.push("-N".to_string());
        args.push("--max-time".to_string());
        args.push("15".to_string());
    }

    let body_string;
    if let Some(body) = body {
        body_string = body.to_string();
        args.push("-d".to_string());
        args.push(body_string);
    }

    args.push("-w".to_string());
    args.push("\n%{http_code}".to_string());
    args.push(url.to_string());

    let output = Command::new("curl")
        .args(args)
        .output()
        .map_err(|e| OwsLibError::BroadcastFailed(format!("failed to run curl: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let (body, status) = stdout.rsplit_once('\n').ok_or_else(|| {
        OwsLibError::BroadcastFailed(format!(
            "Atto HTTP response missing status trailer for {method} {url}"
        ))
    })?;
    let status_code = status.trim().parse::<u16>().map_err(|e| {
        OwsLibError::BroadcastFailed(format!(
            "Atto HTTP response had invalid status trailer `{}`: {e}",
            status.trim()
        ))
    })?;

    if !output.status.success() {
        // curl exits 28 when --max-time is reached. For long-lived Atto NDJSON
        // streams, a timeout after receiving a 2xx response is the expected way
        // to stop reading the subscription and use the records already emitted.
        let curl_timed_out = output.status.code() == Some(28);
        if !(is_ndjson_stream && curl_timed_out && (200..300).contains(&status_code)) {
            return Err(OwsLibError::BroadcastFailed(format!(
                "Atto HTTP transport failed for {method} {url}: {stderr}"
            )));
        }
    }

    if !(200..300).contains(&status_code) {
        let trimmed = body.trim();
        let detail = if trimmed.is_empty() {
            stderr.trim()
        } else {
            trimmed
        };
        return Err(OwsLibError::BroadcastFailed(format!(
            "Atto HTTP {status_code} for {method} {url}: {detail}"
        )));
    }

    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    const ADDRESS: &str = "atto://aaferyy3quqiyugpambc452bu2oqh7hrcazz4vnvem2meaa6thwf4vkiuiwyw";
    const PUBKEY: &str = "44C8865188D6FBE1C084436FF2E08D34538BA0FB2FCB1A8FA76F8127CCF6A281";
    const HASH: &str = "9072A5DB95CF7866F9AF4CC4C12C01F8E1DF903A6A0660EF62986A4B6191BD0C";

    #[test]
    fn account_lookup_by_address_posts_account_search() {
        let account = sample_account_json();
        let (base_url, handle) = serve_once(200, "application/json", &account.to_string());

        let client = AttoNodeClient::new(base_url);
        let result = client.account_by_address(ADDRESS).unwrap().unwrap();
        let request = handle.join().unwrap();

        assert!(request.starts_with("POST /accounts HTTP/1.1"), "{request}");
        assert!(
            request.contains(&format!("\"addresses\":[\"{ADDRESS}\"]")),
            "{request}"
        );
        assert_eq!(result.address, ADDRESS);
        assert_eq!(result.balance, "1000000000000000000");
    }

    #[test]
    fn account_lookup_by_public_key_gets_account_path() {
        let account = sample_account_json();
        let (base_url, handle) = serve_once(200, "application/json", &account.to_string());

        let client = AttoNodeClient::new(base_url);
        let result = client.account_by_public_key(PUBKEY).unwrap().unwrap();
        let request = handle.join().unwrap();

        assert!(
            request.starts_with(&format!("GET /accounts/{PUBKEY} HTTP/1.1")),
            "{request}"
        );
        assert_eq!(result.public_key, PUBKEY);
    }

    #[test]
    fn account_lookup_by_public_key_maps_404_to_none() {
        let (base_url, handle) = serve_once(404, "application/json", r#"{"error":"missing"}"#);

        let client = AttoNodeClient::new(base_url);
        assert!(client.account_by_public_key(PUBKEY).unwrap().is_none());
        let request = handle.join().unwrap();
        assert!(
            request.starts_with(&format!("GET /accounts/{PUBKEY} HTTP/1.1")),
            "{request}"
        );
    }

    #[test]
    fn receivables_are_collected_from_ndjson_stream() {
        let body = format!(
            "{}\n{}\n",
            sample_receivable_json("1"),
            sample_receivable_json("2")
        );
        let (base_url, handle) = serve_once(200, "application/x-ndjson", &body);

        let client = AttoNodeClient::new(base_url);
        let receivables = client
            .list_receivables_by_public_key(PUBKEY, Some("100"))
            .unwrap();
        let request = handle.join().unwrap();

        assert!(
            request.starts_with(&format!(
                "GET /accounts/{PUBKEY}/receivables/stream?minAmount=100 HTTP/1.1"
            )),
            "{request}"
        );
        assert_eq!(receivables.len(), 2);
        assert_eq!(receivables[0].amount, "1");
        assert_eq!(receivables[1].amount, "2");
    }

    #[test]
    fn receivables_for_addresses_post_account_search() {
        let body = format!("{}\n", sample_receivable_json("5"));
        let (base_url, handle) = serve_once(200, "application/x-ndjson", &body);

        let client = AttoNodeClient::new(base_url);
        let receivables = client
            .receivable_stream_by_addresses(&[ADDRESS.to_string()], None)
            .unwrap();
        let request = handle.join().unwrap();

        assert!(
            request.starts_with("POST /accounts/receivables/stream HTTP/1.1"),
            "{request}"
        );
        assert!(
            request.contains(&format!("\"addresses\":[\"{ADDRESS}\"]")),
            "{request}"
        );
        assert_eq!(receivables[0].amount, "5");
    }

    #[test]
    fn live_numeric_account_fields_are_normalized_as_u64_decimal_strings() {
        let account: AttoAccount = serde_json::from_value(serde_json::json!({
            "publicKey": PUBKEY,
            "network": "LIVE",
            "version": 0,
            "algorithm": "V1",
            "height": 2,
            "balance": 900000000,
            "lastTransactionHash": HASH,
            "lastTransactionTimestamp": 1767390950976_i64,
            "representativeAlgorithm": "V1",
            "representativePublicKey": PUBKEY
        }))
        .unwrap();

        assert_eq!(account.height, "2");
        assert_eq!(account.balance, "900000000");
        assert_eq!(account.address, "");
        assert_eq!(account.representative_address, "");
    }

    #[test]
    fn live_numeric_receivable_amount_is_normalized_as_u64_decimal_string() {
        let receivable: AttoReceivable = serde_json::from_value(serde_json::json!({
            "network": "LIVE",
            "hash": HASH,
            "version": 0,
            "algorithm": "V1",
            "publicKey": PUBKEY,
            "timestamp": 1767390950976_i64,
            "receiverAlgorithm": "V1",
            "receiverPublicKey": PUBKEY,
            "amount": 1000000000
        }))
        .unwrap();

        assert_eq!(receivable.amount, "1000000000");
        assert_eq!(receivable.address, "");
        assert_eq!(receivable.receiver_address, "");
    }

    #[test]
    fn u64_decimal_fields_reject_negative_fractional_and_overflow_values() {
        for invalid_amount in [
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("18446744073709551616"),
        ] {
            let err = serde_json::from_value::<AttoReceivable>(serde_json::json!({
                "network": "LIVE",
                "hash": HASH,
                "version": 0,
                "algorithm": "V1",
                "publicKey": PUBKEY,
                "timestamp": 1767390950976_i64,
                "receiverAlgorithm": "V1",
                "receiverPublicKey": PUBKEY,
                "amount": invalid_amount
            }))
            .unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("u64") || message.contains("unsigned 64-bit"),
                "{message}"
            );
        }
    }

    #[test]
    fn time_difference_gets_instant_path() {
        let response = r#"{"clientInstant":1767390950000,"serverInstant":1767390950100,"differenceMillis":100}"#;
        let (base_url, handle) = serve_once(200, "application/json", response);

        let client = AttoNodeClient::new(base_url);
        let diff = client.time_difference(1_767_390_950_000).unwrap();
        let request = handle.join().unwrap();

        assert!(
            request.starts_with("GET /instants/1767390950000 HTTP/1.1"),
            "{request}"
        );
        assert_eq!(diff.difference_millis, 100);
    }

    #[test]
    fn publish_transaction_posts_signed_transaction_and_returns_status() {
        let (base_url, handle) = serve_once(200, "application/json", "");

        let client = AttoNodeClient::new(base_url);
        let result = client.publish_transaction(&sample_transaction()).unwrap();
        let request = handle.join().unwrap();

        assert!(
            request.starts_with("POST /transactions HTTP/1.1"),
            "{request}"
        );
        assert!(request.contains("\"signature\""), "{request}");
        assert_eq!(result.status, AttoPublishStatus::Published);
        assert!(result.hash.is_none());
    }

    #[test]
    fn publish_transaction_stream_returns_transaction_and_hash_when_present() {
        let returned = serde_json::json!({
            "block": {"type":"SEND", "hash": HASH},
            "signature": "00".repeat(64),
            "work": "8E9C4A839AB702AF",
            "address": ADDRESS
        });
        let body = format!("{returned}\n");
        let (base_url, handle) = serve_once(200, "application/x-ndjson", &body);

        let client = AttoNodeClient::new(base_url);
        let result = client
            .publish_transaction_and_stream(&sample_transaction())
            .unwrap();
        let request = handle.join().unwrap();

        assert!(
            request.starts_with("POST /transactions/stream HTTP/1.1"),
            "{request}"
        );
        assert_eq!(result.status, AttoPublishStatus::PublishedAndStreamed);
        assert_eq!(result.hash.as_deref(), Some(HASH));
        assert!(result.transaction.is_some());
    }

    #[test]
    fn work_server_posts_works_request() {
        let response = r#"{"work":"8E9C4A839AB702AF"}"#;
        let (base_url, handle) = serve_once(200, "application/json", response);

        let client = AttoWorkServerClient::new(base_url);
        let work = client
            .work(&AttoWorkRequest {
                network: "LIVE".to_string(),
                timestamp: 1_767_390_950_000,
                target: HASH.to_string(),
            })
            .unwrap();
        let request = handle.join().unwrap();

        assert!(request.starts_with("POST /works HTTP/1.1"), "{request}");
        assert!(request.contains("\"network\":\"LIVE\""), "{request}");
        assert_eq!(work.work, "8E9C4A839AB702AF");
    }

    #[test]
    fn http_error_maps_to_broadcast_failed_with_status_and_body() {
        let (base_url, handle) =
            serve_once(400, "application/json", r#"{"error":"bad transaction"}"#);

        let client = AttoNodeClient::new(base_url);
        let err = client
            .publish_transaction(&sample_transaction())
            .unwrap_err();
        let _ = handle.join().unwrap();

        match err {
            OwsLibError::BroadcastFailed(msg) => {
                assert!(msg.contains("HTTP 400"), "{msg}");
                assert!(msg.contains("bad transaction"), "{msg}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn malformed_json_maps_to_json_error() {
        let (base_url, handle) = serve_once(200, "application/json", "not-json");

        let client = AttoNodeClient::new(base_url);
        let err = client.account_by_public_key(PUBKEY).unwrap_err();
        let _ = handle.join().unwrap();

        match err {
            OwsLibError::Json(_) => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    fn sample_account_json() -> Value {
        serde_json::json!({
            "publicKey": PUBKEY,
            "network": "LIVE",
            "version": 0,
            "algorithm": "V1",
            "height": "1",
            "balance": "1000000000000000000",
            "lastTransactionHash": HASH,
            "lastTransactionTimestamp": 1767390950976_i64,
            "representativeAlgorithm": "V1",
            "representativePublicKey": PUBKEY,
            "representativeAddress": ADDRESS,
            "address": ADDRESS
        })
    }

    fn sample_receivable_json(amount: &str) -> Value {
        serde_json::json!({
            "network": "LIVE",
            "hash": HASH,
            "version": 0,
            "algorithm": "V1",
            "publicKey": PUBKEY,
            "timestamp": 1767390950976_i64,
            "receiverAlgorithm": "V1",
            "receiverPublicKey": PUBKEY,
            "amount": amount,
            "receiverAddress": ADDRESS,
            "address": ADDRESS
        })
    }

    fn sample_transaction() -> AttoTransaction {
        AttoTransaction {
            block: serde_json::json!({
                "type": "SEND",
                "network": "LIVE",
                "version": 0,
                "algorithm": "V1",
                "publicKey": PUBKEY,
                "height": "2",
                "balance": "999999999999999999",
                "timestamp": 1767390950976_i64,
                "address": ADDRESS,
                "previous": HASH,
                "receiverAlgorithm": "V1",
                "receiverPublicKey": PUBKEY,
                "receiverAddress": ADDRESS,
                "amount": "1"
            }),
            signature: "00".repeat(64),
            work: "8E9C4A839AB702AF".to_string(),
            address: ADDRESS.to_string(),
        }
    }

    fn serve_once(
        status: u16,
        content_type: &'static str,
        body: &str,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 16 * 1024];
            let n = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let reason = match status {
                200 => "OK",
                400 => "Bad Request",
                404 => "Not Found",
                _ => "Status",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            stream.write_all(response.as_bytes()).unwrap();
            request
        });
        (format!("http://{addr}"), handle)
    }
}
