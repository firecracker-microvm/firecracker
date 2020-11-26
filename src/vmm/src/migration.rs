use crate::vmm_config::migration::{AcceptMigrationParams, StartMigrationParams};
use std::fmt::{Display, Formatter};
use std::net::{TcpListener, TcpStream};
use std::thread;

/// Errors associated with initiating a migration.
#[derive(Debug)]
pub enum StartMigrationError {
    /// Failed to create TcpListener.
    Tcp(std::io::Error),
}

impl Display for StartMigrationError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::StartMigrationError::*;
        match self {
            Tcp(err) => write!(f, "Failed to create Tcp stream: {}", err.to_string()),
        }
    }
}

/// Errors associated with receiving migration requests.
#[derive(Debug)]
pub enum AcceptMigrationError {
    /// Failed to create TcpListener.
    Tcp(std::io::Error),
}

impl Display for AcceptMigrationError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::AcceptMigrationError::*;
        match self {
            Tcp(err) => write!(f, "Failed to create Tcp listener: {}", err.to_string()),
        }
    }
}

pub fn start_migration(
    start_migration_params: &StartMigrationParams,
) -> Result<(), StartMigrationError> {
    let stream =
        TcpStream::connect(start_migration_params.destination).map_err(StartMigrationError::Tcp)?;

    thread::Builder::new()
        .name("fc_migration".to_string())
        .spawn(move || {});

    Ok(())
}

pub fn accept_migration(
    accept_migration_params: &AcceptMigrationParams,
) -> Result<(), AcceptMigrationError> {
    let listener = TcpListener::bind(accept_migration_params.destination)
        .map_err(AcceptMigrationError::Tcp)?;

    // accept connections and process them serially
    for stream in listener.incoming() {
        println!("incoming connection");
    }

    Ok(())
}
