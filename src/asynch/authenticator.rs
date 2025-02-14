use serde::{Deserialize, Serialize};

use crate::errors::Error;
use std::{future::Future, pin::Pin};

/// Defines the authentication methods supported by the system.
///
/// This enum specifies the different types of authentication that can be used
/// to verify client connections.
///
/// # Variants
///
/// * `RootPassword` - Single password authentication for root access
/// * `UserPassword` - Individual username/password pairs for each user
/// * `None` - No authentication required
///
/// # Example
///
/// ```rust
/// use tnet::asynch::authenticator::AuthType;
///
/// let auth_type = AuthType::UserPassword;
/// match auth_type {
///     AuthType::RootPassword => println!("Using root password authentication"),
///     AuthType::UserPassword => println!("Using per-user authentication"),
///     AuthType::None => println!("No authentication required"),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthType {
    /// One password for everyone no user.
    RootPassword,
    /// Each user has their own password.
    UserPassword,
    /// There is no authentication
    None,
}

/// Type alias for authentication function.
///
/// Represents a function that takes a username and password and returns
/// a future that resolves to a Result indicating authentication success or failure.
///
/// # Type Parameters
///
/// * Input: (`String`, `String`) - Username and password
/// * Output: `Result<(), Error>` - Authentication result
///
/// # Example
///
/// ```rust
/// use tnet::asynch::authenticator::AuthFunction;
///
/// let auth_fn: AuthFunction = |username: String, password: String| {
///     Box::pin(async move {
///         if username == "admin" && password == "secret" {
///             Ok(())
///         } else {
///             Err(Error::InvalidCredentials)
///         }
///     })
/// };
/// ```
pub type AuthFunction = fn(
    username: String,
    password: String,
) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

/**
Main authenticator structure that handles all authentication operations.

The Authenticator provides a flexible authentication system that can handle
different authentication methods and maintain authentication state.

# Fields

* `auth_type` - The type of authentication being used
* `root_password` - Optional root password for `RootPassword` authentication
* `auth_fn` - Optional function for custom authentication logic

# Example

```rust
use tnet::asynch::authenticator::{Authenticator, AuthType};

let auth = Authenticator::new(AuthType::RootPassword)
    .with_root_password("admin123".to_string());
```
*/
#[derive(Debug, Clone)]
pub struct Authenticator {
    pub auth_type: AuthType,
    pub root_password: Option<String>,
    pub auth_fn: Option<AuthFunction>,
}

impl Authenticator {
    /**
    Authenticates a user based on the configured authentication type.

    This method handles all authentication attempts and routes them to
    the appropriate authentication method based on the configuration.

    # Arguments

    * `username` - The username to authenticate
    * `password` - The password to verify

    # Returns

    * `Result<(), Error>` - Ok(()) if authentication succeeds, Error otherwise

    # Example

    ```rust
    async fn authenticate_user(auth: &mut Authenticator) -> Result<(), Error> {
        auth.authenticate("user".to_string(), "pass".to_string()).await
    }
    ```

    # Panics

    This function will panic if:
    - Root password is set but unwrap fails
    - Auth function is set but unwrap fails

    # Errors

    Returns `Error::InvalidCredentials` if:
    - Root password is not set for `RootPassword` authentication
    - Username/password combination is invalid
    - Authentication function is not set for `UserPassword` authentication
    */
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

    /// Creates a new Authenticator instance with the specified authentication type.
    ///
    /// # Arguments
    ///
    /// * `type_` - The type of authentication to use
    ///
    /// # Returns
    ///
    /// * A new Authenticator instance
    ///
    /// # Example
    ///
    /// ```rust
    /// let auth = Authenticator::new(AuthType::UserPassword);
    /// ```
    #[must_use]
    pub fn new(type_: AuthType) -> Self {
        Self {
            auth_type: type_,
            root_password: None,
            auth_fn: None,
        }
    }

    /// Sets the root password for `RootPassword` authentication.
    ///
    /// # Arguments
    ///
    /// * `password` - The root password to set
    ///
    /// # Returns
    ///
    /// * The modified Authenticator instance
    ///
    /// # Example
    ///
    /// ```rust
    /// let auth = Authenticator::new(AuthType::RootPassword)
    ///     .with_root_password("superadmin".to_string());
    /// ```
    #[must_use]
    pub fn with_root_password(mut self, password: String) -> Self {
        self.root_password = Some(password);
        self
    }

    /// Sets the authentication function for `UserPassword` authentication.
    ///
    /// # Arguments
    ///
    /// * `auth_fn` - The function to use for authentication
    ///
    /// # Returns
    ///
    /// * The modified Authenticator instance
    ///
    /// # Example
    ///
    /// ```rust
    /// let auth_fn: AuthFunction = |username, password| {
    ///     Box::pin(async move {
    ///         // Custom authentication logic
    ///         Ok(())
    ///     })
    /// };
    ///
    /// let auth = Authenticator::new(AuthType::UserPassword)
    ///     .with_auth_fn(auth_fn);
    /// ```
    #[must_use]
    pub fn with_auth_fn(mut self, auth_fn: AuthFunction) -> Self {
        self.auth_fn = Some(auth_fn);
        self
    }
}
