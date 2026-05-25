use ows_lib::atto_rpc::{
    AttoAccount, AttoNodeClient, AttoPublishStatus, AttoReceivable, AttoTransaction,
    AttoWorkRequest, AttoWorkResponse, AttoWorkServerClient, TimeDifferenceResponse,
};
use ows_lib::OwsLibError;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

const NODE_FIXTURES: &str = include_str!("fixtures/atto/node_responses.json");
const WORK_FIXTURES: &str = include_str!("fixtures/atto/work_server_responses.json");

fn node_fixtures() -> Value {
    serde_json::from_str(NODE_FIXTURES).expect("valid Atto node fixture JSON")
}

fn work_fixtures() -> Value {
    serde_json::from_str(WORK_FIXTURES).expect("valid Atto work-server fixture JSON")
}

#[test]
fn fixture_node_responses_deserialize_into_rpc_types() {
    let fixtures = node_fixtures();

    let account: AttoAccount = serde_json::from_value(fixtures["account"].clone()).unwrap();
    assert_eq!(account.network, "LIVE");
    assert_eq!(account.balance, "1000000000");
    assert!(account.address.starts_with("atto://"));

    let receivables: Vec<AttoReceivable> =
        serde_json::from_value(fixtures["receivables"].clone()).unwrap();
    assert_eq!(receivables.len(), 2);
    assert_eq!(receivables[0].amount, "1");
    assert_eq!(receivables[1].amount, "2");

    let instant: TimeDifferenceResponse =
        serde_json::from_value(fixtures["instant"].clone()).unwrap();
    assert_eq!(instant.difference_millis, 100);

    let transaction: AttoTransaction =
        serde_json::from_value(fixtures["publish_stream_transaction"].clone()).unwrap();
    assert_eq!(
        transaction.returned_hash(),
        transaction.block["hash"].as_str()
    );
}

#[test]
fn fixture_work_server_responses_deserialize_into_rpc_types() {
    let fixtures = work_fixtures();
    let request: AttoWorkRequest = serde_json::from_value(fixtures["request"].clone()).unwrap();
    let success: AttoWorkResponse = serde_json::from_value(fixtures["success"].clone()).unwrap();

    assert_eq!(request.network, "LIVE");
    assert_eq!(request.target.len(), 64);
    assert_eq!(success.work, "8E9C4A839AB702AF");
}

#[test]
fn node_client_parses_account_receivables_instants_and_publish_fixtures_without_network() {
    let fixtures = node_fixtures();
    let address = fixtures["account"]["address"].as_str().unwrap();
    let public_key = fixtures["account"]["publicKey"].as_str().unwrap();

    let (base_url, account_request) =
        serve_once(200, "application/json", &fixtures["account"].to_string());
    let account = AttoNodeClient::new(base_url)
        .account_by_address(address)
        .unwrap()
        .unwrap();
    assert_eq!(account.address, address);
    assert!(account_request
        .join()
        .unwrap()
        .starts_with("POST /accounts "));

    let receivable_body = fixtures["receivables"]
        .as_array()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let (base_url, receivables_request) = serve_once(200, "application/x-ndjson", &receivable_body);
    let receivables = AttoNodeClient::new(base_url)
        .list_receivables_by_public_key(public_key, Some("1"))
        .unwrap();
    assert_eq!(receivables.len(), 2);
    assert!(receivables_request.join().unwrap().starts_with(&format!(
        "GET /accounts/{public_key}/receivables/stream?minAmount=1 "
    )));

    let (base_url, instant_request) =
        serve_once(200, "application/json", &fixtures["instant"].to_string());
    let instant = AttoNodeClient::new(base_url)
        .time_difference(1_767_390_950_000)
        .unwrap();
    assert_eq!(instant.difference_millis, 100);
    assert!(instant_request
        .join()
        .unwrap()
        .starts_with("GET /instants/1767390950000 "));

    let transaction: AttoTransaction =
        serde_json::from_value(fixtures["publish_stream_transaction"].clone()).unwrap();
    let stream_body = fixtures["publish_stream_transaction"].to_string() + "\n";
    let (base_url, publish_request) = serve_once(200, "application/x-ndjson", &stream_body);
    let published = AttoNodeClient::new(base_url)
        .publish_transaction_and_stream(&transaction)
        .unwrap();
    assert_eq!(published.status, AttoPublishStatus::PublishedAndStreamed);
    assert_eq!(
        published.hash,
        transaction.returned_hash().map(str::to_string)
    );
    assert!(publish_request
        .join()
        .unwrap()
        .starts_with("POST /transactions/stream "));
}

#[test]
fn node_and_work_server_errors_map_to_broadcast_failed_without_network() {
    let node = node_fixtures();
    let transaction: AttoTransaction =
        serde_json::from_value(node["publish_stream_transaction"].clone()).unwrap();
    let (base_url, node_request) =
        serve_once(400, "application/json", &node["publish_error"].to_string());
    let err = AttoNodeClient::new(base_url)
        .publish_transaction(&transaction)
        .unwrap_err();
    assert_broadcast_failed_contains(err, "HTTP 400");
    let _ = node_request.join().unwrap();

    let work = work_fixtures();
    let request: AttoWorkRequest = serde_json::from_value(work["request"].clone()).unwrap();
    let (base_url, work_request) =
        serve_once(503, "application/json", &work["failure"].to_string());
    let err = AttoWorkServerClient::new(base_url)
        .work(&request)
        .unwrap_err();
    assert_broadcast_failed_contains(err, "HTTP 503");
    let _ = work_request.join().unwrap();
}

#[test]
fn work_server_client_posts_fixture_request_without_network() {
    let fixtures = work_fixtures();
    let request: AttoWorkRequest = serde_json::from_value(fixtures["request"].clone()).unwrap();
    let (base_url, handle) = serve_once(200, "application/json", &fixtures["success"].to_string());

    let response = AttoWorkServerClient::new(base_url).work(&request).unwrap();
    let raw_request = handle.join().unwrap();

    assert_eq!(response.work, "8E9C4A839AB702AF");
    assert!(raw_request.starts_with("POST /works "), "{raw_request}");
    assert!(
        raw_request.contains("\"network\":\"LIVE\""),
        "{raw_request}"
    );
}

#[test]
#[ignore = "opt-in live Atto smoke: set ATTO_NODE_URL and run with --ignored"]
fn live_node_time_difference_smoke_requires_env() {
    let node_url = std::env::var("ATTO_NODE_URL").expect("ATTO_NODE_URL must be set");
    let client_instant = std::env::var("ATTO_CLIENT_INSTANT")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(1_767_390_950_000);

    let diff = AttoNodeClient::new(node_url)
        .time_difference(client_instant)
        .expect("live Atto node should return time difference");
    assert_eq!(diff.client_instant, client_instant);
}

fn assert_broadcast_failed_contains(err: OwsLibError, expected: &str) {
    match err {
        OwsLibError::BroadcastFailed(message) => assert!(
            message.contains(expected),
            "expected {expected:?} in broadcast error {message}"
        ),
        other => panic!("unexpected error: {other}"),
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
        let mut buf = [0_u8; 32 * 1024];
        let n = stream.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            503 => "Service Unavailable",
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
