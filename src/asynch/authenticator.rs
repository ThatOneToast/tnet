use crate::errors::Error;
use std::{future::Future, pin::Pin};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthType {
    /// One password for everyone no user.
    RootPassword,
    /// Each user has their own password.
    UserPassword,
    /// There is no authentication
    None,
}

pub type AuthFunction = fn(
    username: String,
    password: String,
) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

#[derive(Debug, Clone)]
pub struct Authenticator {
    pub auth_type: AuthType,
    pub root_password: Option<String>,
    pub auth_fn: Option<AuthFunction>,
}

impl Authenticator {
    pub async fn authenticate(&mut self, username: String, password: String) -> Result<(), Error> {
        match self.auth_type {
            AuthType::RootPassword => {
                if self.root_password.is_none() {
                    return Err(Error::InvalidCredentials);
                }
                if username != "root" || &password != self.root_password.as_ref().unwrap() {
                    return Err(Error::InvalidCredentials);
                }
            }
            AuthType::UserPassword => {
                if self.auth_fn.is_none() {
                    return Err(Error::InvalidCredentials);
                }
                let auth_fn = self.auth_fn.as_ref().unwrap();
                auth_fn(username, password).await?;
            }
            AuthType::None => {}
        }
        Ok(())
    }

    pub fn new(type_: AuthType) -> Self {
        Self {
            auth_type: type_,
            root_password: None,
            auth_fn: None,
        }
    }

    pub fn with_root_password(mut self, password: String) -> Self {
        self.root_password = Some(password);
        self
    }

    pub fn with_auth_fn(mut self, auth_fn: AuthFunction) -> Self {
        self.auth_fn = Some(auth_fn);
        self
    }
}
