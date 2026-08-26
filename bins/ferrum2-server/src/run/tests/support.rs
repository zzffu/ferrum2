pub(super) fn finish_server_test_config(
    path: &std::path::Path,
) -> ferrum2_config::ValidatedServerConfig {
    let prepared = ferrum2_config::prepare_server(path).expect("prepare server test config");
    ferrum2_config::finish_server_v2(
        prepared,
        ferrum2_config::ServerV2Resources::new(Vec::new(), None),
    )
    .expect("finish server test config")
}
