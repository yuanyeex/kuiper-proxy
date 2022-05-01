use std::{time::Duration, sync::Arc, fmt::Result};

use log::info;
use tokio::{net::TcpListener, io};

pub enum AuthTypes {
    // No authentication
    NoAuth = 0x00,
    // Auth by username / password
    UserPass = 0x02,
    // cannot authenticat
    NoMethods = 0xFF,
}

pub struct KuiperProxy {
    listener: TcpListener,
    auth_methods: Arc<Vec<u8>>,
    timeout: Option<Duration>,
}

impl KuiperProxy {
    pub async fn new(
        port: u16,
        ip: &str,
        auth_methods: Vec<u8>,
        timeout: Option<Duration>,
    ) -> io::Result<Self> {
        info!("Listening on {}:{}", ip, port);
        Ok(KuiperProxy {
            listener: TcpListener::bind((ip, port)).await?,
            auth_methods: Arc::new(auth_methods),
            timeout,
        })
    }

    pub async fn serve(&mut self) {
        info!("Serving connections");
    }
}