use std::{path::PathBuf, env};

use kuiper::{AuthTypes, KuiperProxy, User};
use snafu::Error;

use clap::{ArgGroup, Parser};
use log::{info, trace};

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
        env::set_var("RUST_LOG", "kuiper=TRACE")
    }

    pretty_env_logger::init_timed();

    // Initrialize proxy configs

    let mut auth_methods: Vec<u8> = Vec::new();



    // Accept connections without auth
    if config.no_auth {
        auth_methods.push(kuiper::AuthTypes::NoAuth as u8);
    }

    // Enable username/password authentication
    let authed_users: Result<Vec<User>, Box<dyn Error>> = match config.credentials {
        Some(credential_file) => {
            auth_methods.push(AuthTypes::UserPass as u8);
            let mut users: Vec<User> = Vec::new();
            let mut rdr = csv::Reader::from_path(credential_file)?;
            for result in rdr.deserialize() {
                let record: User = result?;

                info!("Loaded user: {}", record.username);
                users.push(record);
            }
            Ok(users)
        },
        _ => Ok(Vec::new()),
    };

    let authed_users = authed_users?;

    let mut kuiper = KuiperProxy::new(config.port, &config.ip, auth_methods, authed_users, None).await?;
    kuiper.serve().await;
    Ok(())
}
