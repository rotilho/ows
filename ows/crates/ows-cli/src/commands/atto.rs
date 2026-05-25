use crate::CliError;

#[allow(clippy::too_many_arguments)]
pub fn send(
    wallet: &str,
    chain: &str,
    to: &str,
    amount: &str,
    index: u32,
    rpc_url: Option<&str>,
    work_url: Option<&str>,
    json_output: bool,
) -> Result<(), CliError> {
    let passphrase = super::read_passphrase();
    let result = ows_lib::atto_send_raw(
        wallet,
        chain,
        to,
        amount,
        Some(&passphrase),
        Some(index),
        rpc_url,
        work_url,
        None,
    )?;
    print_result(result, json_output)
}

pub fn receive(
    wallet: &str,
    chain: &str,
    index: u32,
    rpc_url: Option<&str>,
    work_url: Option<&str>,
    json_output: bool,
) -> Result<(), CliError> {
    let passphrase = super::read_passphrase();
    let result = ows_lib::atto_receive_one(
        wallet,
        chain,
        Some(&passphrase),
        Some(index),
        rpc_url,
        work_url,
        None,
    )?;
    print_result(result, json_output)
}

pub fn change_representative(
    wallet: &str,
    chain: &str,
    representative: &str,
    index: u32,
    rpc_url: Option<&str>,
    work_url: Option<&str>,
    json_output: bool,
) -> Result<(), CliError> {
    let passphrase = super::read_passphrase();
    let result = ows_lib::atto_change_representative(
        wallet,
        chain,
        representative,
        Some(&passphrase),
        Some(index),
        rpc_url,
        work_url,
        None,
    )?;
    print_result(result, json_output)
}

fn print_result(
    result: ows_lib::types::AttoWalletOpResult,
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let hash = result.hash.as_deref().unwrap_or("-");
        println!(
            "{} {} height={} balance={} hash={}",
            result.status, result.block_type, result.height, result.balance, hash
        );
    }
    Ok(())
}
