pub(crate) struct ForwardSpec {
    pub bind_addr: String,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

impl Clone for ForwardSpec {
    fn clone(&self) -> Self {
        Self {
            bind_addr: self.bind_addr.clone(),
            bind_port: self.bind_port,
            target_host: self.target_host.clone(),
            target_port: self.target_port,
        }
    }
}

pub(crate) struct DynamicForwardSpec {
    pub bind_addr: String,
    pub bind_port: u16,
}

impl Clone for DynamicForwardSpec {
    fn clone(&self) -> Self {
        Self {
            bind_addr: self.bind_addr.clone(),
            bind_port: self.bind_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyJumpSpec {
    pub user: Option<String>,
    pub host: String,
    pub port: u16,
}

#[derive(Clone)]
pub(crate) struct RemoteFileInfo {
    pub size: u64,
    pub mtime: u64,
}
