use std::{path::PathBuf, env, ptr::NonNull};

use kuiper::KuiperProxy;
use snafu::Error;

use clap::{ArgGroup, Parser};

const LOGO: &str = r"

 _   __      _       _            
 | | / /     (_)     | |           
 | |/ / _   _ _ _ __ | |_ ___ _ __ 
 |    \| | | | | '_ \| __/ _ | '__|
 | |\  | |_| | | |_) | ||  __| |   
 \_| \_/\__,_|_| .__/ \__\___|_|   
               | |                 
               |_|               
 A SOCKS5 Proxy server powered by Rust              
";

#[derive(Parser, Debug)]
#[clap(version)]
#[clap(group(
    ArgGroup::new("auth").required(true).args(&["no-auth", "credentials"]),
))]
struct Config {
    #[clap(short, long, default_value_t = 1990)]
    // listening port
    port: u16,
    #[clap(short, long, default_value = "127.0.0.1")]
    ip: String,
    #[clap(long)]
    no_auth: bool,
    #[clap(short, long)]
    credentials: Option<PathBuf>
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", LOGO);
    // parse input configs
    let config = Config::parse();

    // logging prepared
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "kuiper=INFO")
    }

    pretty_env_logger::init_timed();

    // Initrialize proxy configs

    let mut auth_methods: Vec<u8> = Vec::new();

    // Accept connections without auth
    if config.no_auth {
        auth_methods.push(kuiper::AuthTypes::NoAuth as u8);
    }

    // Enable username/password authentication
    // TODO, not implemented yet

    let mut kuiper = KuiperProxy::new(config.port, &config.ip, auth_methods, None).await?;
    kuiper.serve().await;
    Ok(())
}
