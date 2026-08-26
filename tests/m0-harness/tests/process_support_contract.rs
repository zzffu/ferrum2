#[path = "../src/local_support/mod.rs"]
mod local_support;

#[test]
fn process_owners_are_linear_bounded_and_fail_closed() {
    local_support::process::assert_process_support_contract();
}

#[test]
fn process_contract_port_child() {
    let Ok(address) = std::env::var("FERRUM2_PROCESS_CONTRACT_ADDRESS") else {
        return;
    };
    let _listener = std::net::TcpListener::bind(address).expect("bind process contract port");
    std::thread::sleep(std::time::Duration::from_secs(30));
}
