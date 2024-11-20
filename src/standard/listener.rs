use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, RwLock},
};

use crate::{
    packet::{NetErrorPacket, NetWrapperPacket, Packet},
    session::Session,
};

use tlogger::prelude::*;

pub fn default_auth_handler(username: &str, password: &str) -> bool {
    if username == "toast" && password == "toast" {
        true
    } else {
        false
    }
}

pub fn default_ok_handler<S: Session, P: Packet>(
    _session: &mut S,
    _packet: P,
    _stream: &mut TcpStream,
) {
    warn!(
        "No Handler",
        "You Have not set a `OK` handler, that is why this message is appearing."
    );
}

/// A TCP network listener that manages sessions and packet handling
///
/// # Type Parameters
/// * `S` - Type implementing Session trait for managing client sessions
/// * `P` - Type implementing Packet trait for network communication
///
/// # Fields
/// * `listener` - TCP listener bound to a specific address
/// * `sessions` - Thread-safe hashmap storing active sessions
/// * `ok_handler` - Callback function for processing valid packets
/// * `auth_handler` - Callback function for authenticating clients
/// * `allow_passthrough` - Flag to enable/disable authentication bypass
///
/// Here is an example from the tests:
///
/// # Example
/// ```rust
///
/// #[cfg(test)]
/// mod tests {
///     use std::{io::Write, net::TcpStream};
///     use super::prelude::*;
///     use t_logger::prelude::*;
///     use uuid::Uuid;
///     use crate::{
///         packet::NetWrapperPacket,
///         standard::{client::Client, listener::Listener},
///     };
///
///    #[derive(DPacket, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
///    struct TestPacket(u8, String, bool);
///
///    impl Default for TestPacket {
///         fn default() -> Self {
///             Self(0, String::new(), false)
///         }
///    }
///
///     #[derive(DSession, Debug, Clone, Serialize, Deserialize)]
///     struct TestSession {
///        #[session_id]
///        id: String,
///        a: bool,
///        b: bool,
///     }
///
///     impl Default for TestSession {
///        fn default() -> Self {
///            Self {
///                id: Uuid::new_v4().to_string(),
///                a: false,
///                b: false,
///             }
///         }
///     }
///
///     fn ok(session: &mut TestSession, packet: TestPacket, stream: &mut TcpStream) {
///         success_box!(
///             format!("[HANDLER] New Packet - {}", session.id).as_str(),
///             "{:?}",
///             packet
///         );
///
///         stream.write(
///             NetWrapperPacket::just_this(
///                 TestPacket::default(),
///                 session.clone()
///             ).encode().as_slice()
///         ).unwrap();
///     }
///
///     #[test]
///     fn start() {
///         let mut server = Listener::new("127.0.0.1:5050");
///         server.set_handler(Box::new(ok));
///         server.allow_passthrough = false;
///         server.listen();
///     }
///
///     #[test]
///     fn client() {
///         let mut client: Client<TestSession> = Client::connect("127.0.0.1:5050").unwrap();
///         client
///             .establish_session("toast".to_string(), "toast".to_string())
///             .unwrap();
///         client.send_packet(TestPacket::default(), false).unwrap();
///
///         let packet: TestPacket = client.receive_packet().unwrap();
///
///         if packet == TestPacket::default() {
///             success_box!("Client", "Packet Received");
///         } else {
///             error_box!("Client", "Packet Received {:?}", packet);
///        }
///     }
/// }
///```
pub struct Listener<S: Session + Send + 'static, P: Packet + Send + 'static> {
    pub listener: TcpListener,
    pub sessions: Arc<RwLock<HashMap<String, S>>>,
    ok_handler: Arc<dyn Fn(&mut S, P, &mut TcpStream) + Send + Sync>,
    auth_handler: Arc<dyn Fn(&str, &str) -> bool + Send + Sync>,
    pub allow_passthrough: bool,
}

impl<S: Session + Send, P: Packet + Send> Listener<S, P> {
    /// Creates a new Listener instance bound to a specific port with a custom packet handler
    ///
    /// # Arguments
    /// * `port` - Port number to bind the listener to
    /// * `handler` - Custom packet handler function
    ///
    /// # Returns
    /// Returns a new Listener instance configured with the specified handler
    pub fn port_w_handler(
        port: u16,
        handler: Box<dyn Fn(&mut S, P, &mut TcpStream) + Send + Sync>,
    ) -> Self {
        Self {
            listener: TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ok_handler: Arc::from(handler),
            allow_passthrough: true,
            auth_handler: Arc::new(default_auth_handler),
        }
    }

    /// Creates a new Listener instance bound to a specified address
    ///
    /// # Arguments
    /// * `addr` - Address string to bind the listener to (e.g., "127.0.0.1:8080")
    ///
    /// # Returns
    /// Returns a new Listener instance with default handlers
    pub fn new(addr: &str) -> Self {
        Self {
            listener: TcpListener::bind(addr).unwrap(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ok_handler: Arc::new(default_ok_handler),
            allow_passthrough: true,
            auth_handler: Arc::new(default_auth_handler),
        }
    }

    /// Sets a custom authentication handler for the listener
    ///
    /// # Arguments
    /// * `handler` - Custom authentication handler function
    pub fn set_auth_handler(&mut self, handler: Box<dyn Fn(&str, &str) -> bool + Send + Sync>) {
        self.auth_handler = Arc::from(handler);
    }

    /// Sets a custom packet handler for the listener
    ///
    /// # Arguments
    /// * `handler` - Custom packet handler function
    pub fn set_handler(&mut self, handler: Box<dyn Fn(&mut S, P, &mut TcpStream) + Send + Sync>) {
        self.ok_handler = Arc::from(handler);
    }

    /// Starts the server and begins listening for incoming connections
    ///
    /// This method runs in an infinite loop, spawning new threads for each client connection.
    /// Handles authentication, session management, and packet processing according to the
    /// configured handlers.
    pub fn listen(&mut self) {
        loop {
            let (stream, addr) = self.listener.accept().unwrap();
            info!("New Connection", "Connection from {}", addr.to_string());

            let ok_handler = Arc::clone(&self.ok_handler);
            let auth_handler = Arc::clone(&self.auth_handler);
            let allow_passthrough = self.allow_passthrough;
            let sessions = Arc::clone(&self.sessions);

            std::thread::spawn(move || {
                let mut stream = stream;
                loop {
                    let mut buf = [0; 1024];
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            // Connection closed by client
                            info!(format!("{}", addr.to_string()), "Connection closed");
                            break;
                        }
                        Ok(_) => {
                            let packet: NetWrapperPacket = NetWrapperPacket::decode(&buf);
                            debug_box!("New Packet", "{:?}", packet);

                            match packet.action_id {
                                0 => {
                                    // If passthrough is enabled it will bypass authentication.
                                    if allow_passthrough {
                                        let mut empty_session = S::default();
                                        let mut wsess = sessions.write().unwrap();
                                        let mut session = wsess
                                            .get_mut(&packet.session_id)
                                            .unwrap_or(&mut empty_session);
                                        (ok_handler.as_ref())(
                                            &mut session,
                                            P::decode(&packet.packet.unwrap()),
                                            &mut stream,
                                        );
                                        info!(
                                            format!("{}", addr.to_string()),
                                            "Passthrough Successful"
                                        );
                                    } else {
                                        warn!(
                                            "Invalid Passthrough",
                                            "**{}** Sent a passthrough packet, but this server doesn't allow passthroughs",
                                            addr.to_string()
                                        );
                                    }
                                }
                                1 => {
                                    // A client is requesting for a session.
                                    let p_user = packet.username;
                                    let p_pass = packet.password;

                                    if p_user.is_none() || p_pass.is_none() {
                                        warn!(
                                            "Invalid Auth Packet",
                                            "**{}** Sent an invalid auth packet",
                                            addr.to_string()
                                        );
                                        continue;
                                    }

                                    let user = p_user.unwrap();
                                    let pass = p_pass.unwrap();

                                    if (auth_handler)(&user, &pass) {
                                        let session = S::default();
                                        let ses_id = session.get_id();

                                        let return_packet = NetWrapperPacket {
                                            action_id: 1,
                                            session_id: ses_id.clone(),
                                            ..Default::default()
                                        };

                                        sessions.write().unwrap().insert(ses_id.clone(), session);

                                        stream.write(return_packet.encode().as_slice()).unwrap();
                                        info!(format!("{}", addr.to_string()), "Authenticated");
                                    } else {
                                        let return_packet = NetWrapperPacket {
                                            action_id: 2,
                                            packet: Some(
                                                NetErrorPacket::new(
                                                    "Invalid Credentials".to_string(),
                                                )
                                                .encode(),
                                            ),
                                            ..Default::default()
                                        };

                                        warn!(
                                            "Invalid Auth Packet",
                                            "**{}** Sent an invalid auth packet, Their credentials were invalid",
                                            addr.to_string()
                                        );

                                        stream.write(return_packet.encode().as_slice()).unwrap();
                                    }
                                }
                                3 => {
                                    let passed_ses_id = &packet.session_id;

                                    let mut sessions = sessions.write().unwrap();
                                    let session = sessions.get_mut(passed_ses_id);

                                    if session.is_none() {
                                        warn!(
                                            "Invalid Session",
                                            "**{}** Sent an invalid session packet",
                                            addr.to_string()
                                        );
                                        continue;
                                    }

                                    let data_packet = packet.packet;

                                    if data_packet.is_none() {
                                        warn!(
                                            "Invalid Packet",
                                            "**{}** Sent an invalid packet, underlying packet was None",
                                            addr.to_string(),
                                        );
                                        continue;
                                    }

                                    let mut session = session.unwrap();
                                    let packet = P::decode(&data_packet.unwrap());
                                    debug!(
                                        "Responding to Client w/ Handler",
                                        "Sending to handler: {:?}", packet
                                    );
                                    (ok_handler)(&mut session, packet, &mut stream);
                                }
                                _ => {
                                    warn!(
                                        "Invalid Packet",
                                        "**{}** Sent an invalid packet",
                                        addr.to_string()
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("Read Error", "Error reading from socket: {}", e);
                            break;
                        }
                    }
                }
            });
        }
    }
}

/// Macro to read and decode a packet from a TCP stream
///
/// # Arguments
/// * `$stream:expr` - The TcpStream to read from
/// * `$packet_type:ty` - The type of packet to decode into
///
/// # Returns
/// * `Result<$packet_type, std::io::Error>` - The decoded packet or an error
///
/// # Example
/// ```rust
/// let packet: DicePacket = read_packet!(stream, DicePacket)?;
/// ```
#[macro_export]
macro_rules! read_packet {
    ($stream:expr, $packet_type:ty) => {{
        let mut buf = [0; 1024];
        match $stream.read(&mut buf) {
            Ok(0) => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed",
            )),
            Ok(_) => {
                let wrapper: NetWrapperPacket = NetWrapperPacket::decode(&buf);
                match wrapper.packet {
                    Some(packet_data) => Ok(<$packet_type>::decode(&packet_data)),
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "No packet data received",
                    )),
                }
            }
            Err(e) => Err(e),
        }
    }};
}
