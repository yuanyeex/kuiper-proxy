use std::{time::Duration, sync::Arc, vec};

use log::{info, debug, warn, trace};
use serde_derive::Deserialize;
use snafu::Snafu;
use thiserror::Error;
use tokio::{net::TcpListener, io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, AsyncReadExt}, sync::watch::error, time::Timeout};

/// Version of socks
const SOCKS_VERSION: u8 = 0x05;
const RESERVED: u8 = 0x00;

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct User {
    pub username: String,
    password: String
}

pub struct SocksProtocol {
    // As rfc 1928 (S6)
    // the server evaluates the request, and returns a reply formed as follows:
    //
    //    +----+-----+-------+------+----------+----------+
    //    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //    +----+-----+-------+------+----------+----------+
    //    | 1  |  1  | X'00' |  1   | Variable |    2     |
    //    +----+-----+-------+------+----------+----------+
    //
    buf: [u8; 10],
}

impl SocksProtocol {
    pub fn new(status: ResponseCode) -> Self {
        let buf = [
            // VER
            SOCKS_VERSION, 
            // REP
            status as u8, 
            // RSV
            RESERVED, 
            // ATYPS
            1, 
            // BND.ADDR
            0, 0, 0, 0,
            // BND.PORT 
            0, 0
        ];
        Self{ buf }
    }

    pub async fn send<T>(&self, stream: &mut T) -> io::Result<()> 
    where T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        stream.write_all(&self.buf[..]).await?;
        Ok(())
    }
}

#[derive(Debug, Snafu)]
pub enum ResponseCode {
    Success = 0x00,
    #[snafu(display("SOCKS Server Failure"))]
    Failure = 0x01,
    #[snafu(display("SOCKS RUle Failure"))]
    RuleFailure = 0x02,
    #[snafu(display("Network unreachable"))]
    NetworkUnReachable = 0x03,
    #[snafu(display("Host unreachable"))]
    HostUnreachable = 0x04,
    #[snafu(display("Connection refused"))]
    ConnectionRefused = 0x05,
    #[snafu(display("TTL expired"))]
    TtlExpired = 0x06,
    #[snafu(display("Command not supported"))]
    CommandNotSupported = 0x07,
    #[snafu(display("Addr Type not supported"))]
    AddrTypeNotSupported = 0x008
}

impl From<KuiperError> for ResponseCode{
    fn from(e: KuiperError) -> Self {
        match e {
            KuiperError::Socks(e) => e,
            KuiperError::Io(_) => ResponseCode::Failure,
        }
    }
}

enum AddrType {
    v4 = 0x01,
    Domain = 0x03,
    v6 = 0x04
}
#[derive(Debug)]
enum SockCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssosiate = 0x03,
}

impl SockCommand {
    fn from(n: usize) -> Option<SockCommand> {
        match n {
            1 => Some(SockCommand::Connect),
            2 => Some(SockCommand::Bind),
            3 => Some(SockCommand::UdpAssosiate),
            _ => None,
        }
    }
}

#[derive(Error, Debug)]
pub enum KuiperError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Socks error: {0}")]
    Socks(#[from] ResponseCode)
}

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
        while let Ok((stream, client_addr)) = self.listener.accept().await {
            // currently all 
            let auth_methods = self.auth_methods.clone();
            let timeout = self.timeout.clone();

            tokio::spawn(async move {
                let mut client = SOCKClient::new
            })
        }
    }
}

pub struct SockClient<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    stream: T,
    auth_nmethods: u8,
    auth_methods: Arc<Vec<u8>>,
    authed_users: Arc<Vec<User>>,
    socks_version: u8,
    timeout: Option<Duration>,
}

impl <T> SockClient<T> where T: AsyncRead + AsyncWrite + Send + Unpin + 'static, {
    pub fn new (
        stream: T,
        authed_users: Arc<Vec<User>>,
        auth_methods: Arc<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Self {
        SockClient { 
            stream, 
            auth_nmethods: 0, 
            socks_version: 0, 
            authed_users,
            auth_methods,
            timeout, 
        }
    }

    pub fn new_no_auth(stream: T, timeout: Option<Duration>) -> Self {
        // FIXME: use option here
        let authed_users:Arc<Vec<User>> = Arc::new(Vec::new());
        let mut no_auth = Vec::new();
        no_auth.push(AuthTypes::NoAuth as u8);
        let auth_methods = Arc::new(no_auth);

        SockClient { stream, auth_nmethods: 0, authed_users, auth_methods, socks_version: 0, timeout, }
    }

    pub fn stream_mut(&mut self, user: &User) -> &mut T {
        &mut self.stream
    }

    fn authed(&self, user: &User) -> bool {
        self.authed_users.contains(user)
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    pub async fn init(&mut self) -> Result<(), KuiperError> {
        debug!("New Connection");
        let mut header = [0u8; 2];
        // read a byte from the stream and determin the version being requested;
        self.stream.read_exact(&mut header).await?;
        self.stream.read_exact(&mut header).await?;

        self.socks_version = header[0];
        self.auth_nmethods = header[1];

        trace!("Version: {}, Auth methods: {}", self.socks_version, self.auth_nmethods);

        match self.socks_version {
            SOCKS_VERSION => {
                self.auth().await?;
                self.handle_client().await?
            }
            _ => {
                warn!("Init: unsupported version: SOCKS{}" , &self.socks_version);
                self.shutdown().await?;
            }
        }

        Ok(())
    }

    pub async fn handle_client(&mut self) -> Result<usize, KuiperError> {
        debug!("Starting to read data");

        let req = SockReque
    }

    async fn auth(&mut self) -> Result<(), KuiperError> {
        debug!("Authentication!");
        // get valid auth methods
        let methods = self.get_available_methods().await?;
        trace!("methods: {:?}", methods);

        let mut response = [0u8; 2];
        response[0] = SOCKS_VERSION;

        if methods.contains(&(AuthTypes::UserPass as u8)) {
            // set the default auth method No AUTH
            response[1] = AuthTypes::UserPass as u8;

            debug!("Sending User/Pass packet");
            self.stream.write_all(&response).await?;

            let mut header = [0u8; 2];

            // read a byte from the stream and determin the version being requested
            self.stream.read_exact(&mut header).await?;

            debug!("Auth header: [{}, {}]", header[0], header[1]);

            // user name parsing
            let mut username = vec![0; ulen];
            self.stream.read_exact(&mut username).await?;

            // Password read
            let mut plen = [0u8, 1];
            self.stream.read_exact(&mut plen).await?;

            let mut password = vec![0,; plen[0] as usize];
            self.stream.read_exact(&mut password).await?;

            let user = User {username, password}; 

            if self.authed(&user) {
                debug!("Access Granted. User: {}", user.username);
                let response = [1, ResponseCode::Success as u8];
                self.stream.write_all(&response).await?;
            } else {
                debug!("Access Denied. User: {}", user.username);
                let response = [1, ResponseCode::Failure as u8];
                self.stream.write_all(&response).await?;

                self.shutdown().await?;
            }

            Ok(())
        } else if methods.contains(&(AuthTypes::NoAuth as u8)) {
            // set the auth method to no auth 
            response[1] = AuthTypes::NoAuth as u8;
            debug!("Sending NOAUTH packet");
            self.stream.write_all(&response).await?;
            debug!("NOAUTH sent");
            Ok(())
        } else {
            warn!("Client hash no suitable Auth methods!");
            response[1] = AuthTypes::NoMethods as u8;
            self.stream.write_all(&response).await?;
            self.shutdown().await?;

            Err(KuiperError::Socks(ResponseCode::Failure))
        }

    
    }

    async fn get_available_methods(&mut self) -> io::Result<Vec<u8>> {
        let mut methods = Vec::with_capacity(self.auth_nmethods as usize);
        for _ in 0..self.auth_nmethods {
            let mut method = [0u8, 1];
            self.stream.read_exact(&mut method).await?;
            if self.auth_methods.contains(&method[0]) {
                methods.append(&mut method.to_vec());
            }
        }
        Ok(methods)
    }
}


struct SocksRequest {
    pub version: u8,
    pub command: SockCommand,
    pub addr_type: AddrType,
    pub addr: Vec<u8>,
    pub port: u16,
}

// impl SocksRequest {
//     async fn from_stream<T>(stream: &mut T) -> Result<Self, KuiperError> where T: AsyncRead + AsyncWrite + Send + Unpin + 'static, {
//         // from rfc 1928 (S4), the socks request is formed as follow:
//         // 
//         //    +----+-----+-------+------+----------+----------+
//         //    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//         //    +----+-----+-------+------+----------+----------+
//         //    | 1  |  1  | X'00' |  1   | Variable |    2     |
//         //    +----+-----+-------+------+----------+----------+


//     }

}