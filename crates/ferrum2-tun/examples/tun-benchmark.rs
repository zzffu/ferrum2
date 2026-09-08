fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [scenario_flag, scenario, mode_flag, mode] = arguments.as_slice() else {
        eprintln!("usage: tun-benchmark --scenario NAME --mode Quick|Confirm");
        std::process::exit(2);
    };
    if scenario_flag != "--scenario" || mode_flag != "--mode" {
        eprintln!("usage: tun-benchmark --scenario NAME --mode Quick|Confirm");
        std::process::exit(2);
    }
    match ferrum2_tun::benchmark::trial(scenario, mode) {
        Ok(trial) => println!("{trial}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
