use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
    os::unix::thread,
    sync::{Arc, RwLock},
};

use crate::{
    packet::{NetErrorPacket, NetWrapperPacket, Packet},
    session::Session,
    warn,
};

pub fn default_auth_handler(username: &str, password: &str) -> bool {
    if username == "toast" && password == "toast" {
        true
    } else {
        false
    }
}

pub fn default_ok_handler<S: Session, P: Packet>(_session: &mut S, _packet: P) {
    warn!("You Have not set a `OK` handler, that is why this message is appearing.");
}

pub struct Listener<S: Session + Send + 'static, P: Packet + Send + 'static> {
    listener: TcpListener,
    sessions: Arc<RwLock<HashMap<String, S>>>,
    ok_handler: Arc<dyn Fn(&mut S, P) + Send + Sync>,
    auth_handler: Arc<dyn Fn(&str, &str) -> bool + Send + Sync>,
    pub allow_passthrough: bool,
}

impl<S: Session + Send, P: Packet + Send> Listener<S, P> {
    pub fn port_w_handler(port: u16, handler: Box<dyn Fn(&mut S, P) + Send + Sync>) -> Self {
        Self {
            listener: TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ok_handler: Arc::from(handler),
            allow_passthrough: true,
            auth_handler: Arc::new(default_auth_handler),
        }
    }

    pub fn new(addr: &str) -> Self {
        Self {
            listener: TcpListener::bind(addr).unwrap(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ok_handler: Arc::new(default_ok_handler),
            allow_passthrough: true,
            auth_handler: Arc::new(default_auth_handler),
        }
    }

    pub fn set_auth_handler(&mut self, handler: Box<dyn Fn(&str, &str) -> bool + Send + Sync>) {
        self.auth_handler = Arc::from(handler);
    }

    pub fn set_handler(&mut self, handler: Box<dyn Fn(&mut S, P) + Send + Sync>) {
        self.ok_handler = Arc::from(handler);
    }

    /// Start the server and listen for connections.
    pub fn listen(&mut self) {
        loop {
            let (mut stream, addr) = self.listener.accept().unwrap();
            println!("Connection from {}", addr.to_string());

            let mut buf = [0; 1024];
            stream.read(&mut buf).unwrap();

            let packet: NetWrapperPacket = NetWrapperPacket::decode(&buf);

            println!("Got packet ::: {:?}", packet);

            let ok_handler = Arc::clone(&self.ok_handler);
            let auth_handler = Arc::clone(&self.auth_handler);
            let allow_passthrough = self.allow_passthrough;
            let sessions = Arc::clone(&self.sessions);

            std::thread::spawn(move || {
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
                        }

                        let user = p_user.unwrap();
                        let pass = p_pass.unwrap();

                        if (auth_handler)(&user, &pass) {
                            let session = S::default();
                            let ses_id = session.get_id();
                            sessions.write().unwrap().insert(ses_id.clone(), session);

                            let return_packet = NetWrapperPacket {
                                action_id: 1,
                                session_id: ses_id,
                                ..Default::default()
                            };

                            stream.write(return_packet.encode().as_slice()).unwrap();
                        } else {
                            let return_packet = NetWrapperPacket {
                                action_id: 2,
                                packet: Some(
                                    NetErrorPacket::new("Invalid Credentials".to_string()).encode(),
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

                        println!("Got the packet of {:?}", packet);

                        if session.is_none() {
                            warn!(
                                "Invalid Session",
                                "**{}** Sent an invalid session packet",
                                addr.to_string()
                            );
                        }

                        let data_packet = packet.packet;

                        if data_packet.is_none() {
                            warn!(
                                "Invalid Packet",
                                "**{}** Sent an invalid packet, underlying packet was None",
                                addr.to_string(),
                            );
                        }

                        println!("Sending to handler");

                        let mut session = session.unwrap();
                        let packet = P::decode(&data_packet.unwrap());
                        (ok_handler)(&mut session, packet);
                    }
                    _ => {
                        warn!(
                            "Invalid Packet",
                            "**{}** Sent an invalid packet",
                            addr.to_string()
                        );
                    }
                }
            });
        }
    }
}
