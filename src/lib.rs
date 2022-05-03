use std::{time::Duration, sync::Arc, vec};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use log::{info, debug, warn, trace, error};
use serde_derive::Deserialize;
use snafu::Snafu;
use thiserror::Error;
use tokio::{net::TcpListener, io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, AsyncReadExt}};
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;

/// Version of socks
const SOCKS_VERSION: u8 = 0x05;
const RESERVED: u8 = 0x00;

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct User {
    pub username: String,
    password: String
}

pub struct SocksReply {
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

impl SocksReply {
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
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x04,
}

impl AddrType {
    fn from(n: usize) -> Option<AddrType> {
        match n {
            1 => Some(AddrType::V4),
            3 => Some(AddrType::Domain),
            4 => Some(AddrType::V6),
            _ => None,
        }
    }
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
    users: Arc<Vec<User>>,
    auth_methods: Arc<Vec<u8>>,
    timeout: Option<Duration>,
}

impl KuiperProxy {
    pub async fn new(
        port: u16,
        ip: &str,
        auth_methods: Vec<u8>,
        users: Vec<User>,
        timeout: Option<Duration>,
    ) -> io::Result<Self> {
        info!("Listening on {}:{}", ip, port);
        Ok(KuiperProxy {
            listener: TcpListener::bind((ip, port)).await?,
            auth_methods: Arc::new(auth_methods),
            users: Arc::new(users),
            timeout,
        })
    }

    pub async fn serve(&mut self) {
        info!("Serving connections");
        while let Ok((stream, client_addr)) = self.listener.accept().await {
            // currently all
            let auth_methods = self.auth_methods.clone();
            let timeout = self.timeout.clone();
            let users = self.users.clone();
            tokio::spawn(async move {
                let mut client = SockClient::new(stream, users, auth_methods, timeout);
                match client.init().await {
                    Ok(_) => {
                        trace!("Client init ok.. ");
                    },
                    Err(error) => {
                        error!("Error! {:?}, client {:?}", error, client_addr);
                        if let Err(e) = SocksReply::new(error.into()).send(&mut client.stream).await
                        {
                            warn!("Failed to send error code: {:?}", e);
                        }

                        if let Err(e) = client.shutdown().await {
                            warn!("Failed to shutdown TcpStream: {:?}", e);
                        }
                    }
                }
            });
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


    pub fn stream_mut(&mut self) -> &mut T {
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

        self.socks_version = header[0];
        self.auth_nmethods = header[1];

        trace!("Version: {}, Auth methods: {}", self.socks_version, self.auth_nmethods);

        match self.socks_version {
            SOCKS_VERSION => {
                self.auth().await?;
                self.handle_client().await?;
            },
            _ => {
                warn!("Init: unsupported version: SOCKS{}" , &self.socks_version);
                self.shutdown().await?;
            },
        }

        Ok(())
    }

    pub async fn handle_client(&mut self) -> Result<usize, KuiperError> {
        debug!("Starting to read data");

        let req = SocksRequest::from_stream(&mut self.stream).await?;

        let displayed_addr = pretty_print_addr(&req.addr_type, &req.addr);

        info!("New Request: Command: {:?} addr: {} port {}", req.command, displayed_addr, req.port);

        // Response
        match req.command {
            // Use the Proxy to connect to the specified addr/port
            SockCommand::Connect => {
                debug!("Handling Connect Command");
                let sock_addr = addr_to_socket(&req.addr_type, &req.addr, req.port).await?;
                trace!("Connecting to {:?}", sock_addr);

                let time_out = if let Some(time_out) = self.timeout {
                    time_out
                } else {
                    Duration::from_millis(50)
                };

                let mut target =
                    timeout(
                        time_out,
                    async move {TcpStream::connect(&sock_addr[..]).await },
                    )
                    .await
                        .map_err(|_| KuiperError::Socks(ResponseCode::AddrTypeNotSupported))
                        .map_err(|_| KuiperError::Socks(ResponseCode::AddrTypeNotSupported))??;

                trace!("Connected!");
                SocksReply::new(ResponseCode::Success)
                    .send(&mut self.stream)
                    .await?;

                trace!("copy bidirectional");
                match io::copy_bidirectional(&mut self.stream, &mut target).await {
                    // ignore not connected for shutdown error
                    Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                        trace!("already closed");
                        Ok(0)
                    },
                    Err(e) => Err(KuiperError::Io(e)),
                    Ok((_s_to_t, t_to_s)) => Ok(t_to_s as usize),
                }
            },
            SockCommand::Bind => Err(KuiperError::Io(io::Error::new(io::ErrorKind::Unsupported, "Bind not supported"))),
            SockCommand::UdpAssosiate => Err(KuiperError::Io(io::Error::new(io::ErrorKind::Unsupported, "UdpAssosiate not supported"))),
        }
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
            let ulen = header[1] as usize;
            let mut username = vec![0; ulen];
            self.stream.read_exact(&mut username).await?;

            // Password read
            let mut plen = [0u8, 1];
            self.stream.read_exact(&mut plen).await?;

            let mut password = vec![0; plen[0] as usize];
            self.stream.read_exact(&mut password).await?;

            let username = String::from_utf8_lossy(&username).to_string();
            let password = String::from_utf8_lossy(&password).to_string();

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
        trace!("n auth method: {}", self.auth_nmethods);
        let mut methods = Vec::with_capacity(self.auth_nmethods as usize);
        for _ in 0..self.auth_nmethods {
            let mut method = [0u8; 1];
            self.stream.read_exact(&mut method).await?;
            trace!("check auth type {}, against {:?}", &method[0], self.auth_methods.clone());
            if self.auth_methods.contains(&method[0]) {
                methods.append(&mut method.to_vec());
            }
        }
        trace!("checked methods: {:?}", &methods);
        Ok(methods)
    }
}

async fn addr_to_socket(addr_type: &AddrType, addr: &[u8], port: u16) -> io::Result<Vec<SocketAddr>> {
    match addr_type {
        AddrType::V6 => {
            let new_addr = (0..8)
                .map(|x| {
                    trace!("{} and {}", x*2, x*2 - 1);
                    u16::from(addr[(x * 2)]) << 8 | u16::from(addr[(x*2) + 1])
                })
                .collect::<Vec<u16>>();

            Ok(vec![SocketAddr::from(SocketAddrV6::new(
                Ipv6Addr::new(
                    new_addr[0],
                    new_addr[1],
                    new_addr[2],
                    new_addr[3],
                    new_addr[4],
                    new_addr[5],
                    new_addr[6],
                    new_addr[7],
                ),
                port,
                0,
                0
            ))])
        },
        AddrType::V4 => Ok(vec![SocketAddr::from(SocketAddrV4::new(
            Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
            port,
        ))]),
        AddrType::Domain => {
            let mut domain = String::from_utf8_lossy(addr).to_string();
            domain.push(':');
            domain.push_str(&port.to_string());

            Ok(lookup_host(domain).await?.collect())
        }
    }
}

// convert and addr type and address to string
fn pretty_print_addr(addr_type: &AddrType, addr: &[u8]) -> String {
    match addr_type {
        AddrType::Domain => String::from_utf8_lossy(addr).to_string(),
        AddrType::V4 => addr.iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<String>>()
            .join("."),
        AddrType::V6 => {
            let addr_16 = (0..8)
                .map(|x|(u16::from(addr[x * 2]) << 8 | u16::from(addr[(x * 2) + 1])))
                .collect::<Vec<u16>>();

            addr_16
                .iter()
                .map(|x| format!("{:x}", x))
                .collect::<Vec<String>>()
                .join(":")
        }
    }
}

#[allow(dead_code)]
struct SocksRequest {
    pub version: u8,
    pub command: SockCommand,
    pub addr_type: AddrType,
    pub addr: Vec<u8>,
    pub port: u16,
}

impl SocksRequest {
    // Parse a SOCKS request from a TcpStream
    async fn from_stream<T>(stream: &mut T) -> Result<Self, KuiperError>
        where
            T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // From rfc 1928 (S4), the socks request is formed as:
        //
        //    +----+-----+-------+------+----------+----------+
        //    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        //    +----+-----+-------+------+----------+----------+
        //    | 1  |  1  | X'00' |  1   | Variable |    2     |
        //    +----+-----+-------+------+----------+----------+
        trace!("Server waiting for connect");
        let mut packet = [0u8; 4];
        // Read a byte from the stream and determine the version being requested
        stream.read_exact(&mut packet).await?;
        trace!("Server received: {:?}", packet);
        if packet[0] != SOCKS_VERSION {
            warn!("from_stream Unsupported version: SOCKS{}", packet[0]);
            stream.shutdown().await?;
        }

        // get command
        let command = match SockCommand::from(packet[1] as usize) {
            Some(cmd) => Ok(cmd),
            None => {
                warn!("Invalid Command");
                stream.shutdown().await?;
                Err(KuiperError::Socks(ResponseCode::CommandNotSupported))
            }
        }?;

        // get addr
        trace!("Get addr type!");
        let addr_type = match AddrType::from(packet[3] as usize) {
            Some(addr) => Ok(addr),
            None => {
                error!("No addr type");
                stream.shutdown().await?;
                Err(KuiperError::Socks(ResponseCode::AddrTypeNotSupported))
            }
        }?;

        trace!("Get Addr!");
        // Get adddr from addr_type and stream
        let addr: Vec<u8> = match addr_type {
            AddrType::Domain => {
                let mut dlen = [0u8; 1];
                stream.read_exact(&mut dlen).await?;
                let mut domain = vec![0u8; dlen[0] as usize];
                stream.read_exact(&mut domain).await?;
                domain
            },
            AddrType::V4 => {
                let mut addr = vec![0u8; 4];
                stream.read_exact(&mut addr).await?;
                addr
            },
            AddrType::V6 => {
                let mut addr = vec![0u8; 16];
                stream.read_exact(&mut addr).await?;
                addr
            }
        };
        // Read DST.port
        let mut port = [0u8, 2];
        stream.read_exact(&mut port).await?;

        let port = u16::from(port[0]) << 8 | u16::from(port[1]);

        // Return parsed requet
        Ok(SocksRequest{
            version: packet[0],
            command,
            addr_type,
            addr,
            port
        })
    }
}

