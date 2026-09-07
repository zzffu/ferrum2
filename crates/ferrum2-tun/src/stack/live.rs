use super::Stack;

impl Stack {
    pub(crate) fn start_tcp(
        &mut self,
        runtime: &tokio::runtime::Handle,
    ) -> std::io::Result<Vec<ferrum2_platform_windows::TcpIngressEndpoint>> {
        self.system_tcp.start(self.addresses, runtime)
    }

    pub(crate) fn tcp_failed(&self) -> bool {
        self.system_tcp.failed()
    }

    pub(crate) fn stop_tcp_and_join(&mut self) -> Result<(), ()> {
        self.system_tcp.stop_and_join()
    }
}
