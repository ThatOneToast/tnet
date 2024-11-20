use std::collections::HashMap;
use std::sync::Arc;

use tlogger::prelude::*;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::packet::NetErrorPacket;
use crate::packet::NetWrapperPacket;
use crate::prelude::*;

pub fn default_auth_handler(_username: &str, _password: &str) -> bool {
    warn!(
        "No Auth Handler",
        "You Have not set an `Auth` handler, that is why this message is appearing. Allowing bypass."
    );
    true
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

pub struct Listener<S: Session + Send + 'static, P: Packet + Send + 'static> {
    pub listener: TcpListener,
    pub sessions: Arc<RwLock<HashMap<String, S>>>,
    ok_handler: Arc<dyn Fn(&mut S, P, &mut TcpStream) + Send + Sync>,
    auth_handler: Arc<dyn Fn(&str, &str) -> bool + Send + Sync>,
    pub allow_passthrough: bool,
}

impl<S: Session + Send, P: Packet + Send> Listener<S, P> {
    pub async fn port_w_handler(
        port: u16,
        handler: Box<dyn Fn(&mut S, P, &mut TcpStream) + Send + Sync>,
    ) -> Self {
        Self {
            listener: TcpListener::bind(format!("127.0.0.1:{}", port)).await.unwrap(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ok_handler: Arc::from(handler),
            allow_passthrough: true,
            auth_handler: Arc::new(default_auth_handler),
        }
    }
    
    pub async fn new(addr: &str) -> Self {
        Self {
            listener: TcpListener::bind(addr).await.unwrap(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ok_handler: Arc::new(default_ok_handler),
            allow_passthrough: true,
            auth_handler: Arc::new(default_auth_handler),
        }
    }
    
    pub async fn listen(&mut self) {
        loop {
            let (mut stream, addr) = self.listener.accept().await.unwrap();
            info!("New Connection", "Connection from {}", addr.to_string());
            
            let ok_handler = Arc::clone(&self.ok_handler);
            let auth_handler = Arc::clone(&self.auth_handler);
            let allow_passthrough = self.allow_passthrough;
            let sessions = Arc::clone(&self.sessions);
            tokio::spawn(async move {
                loop {
                    let mut buf = [0; 1024];
                    let read_res = stream.read(&mut buf).await;
                    let read = match read_res {
                        Ok(0) => {
                            error!("Connection Closed", "Connection closed");
                            break;
                        },
                        Ok(_) => {
                            let packet: NetWrapperPacket = NetWrapperPacket::decode(&buf);
                            debug_box!(format!("New Packet f/ {}", addr.to_string()).as_str(), "{:?}", packet);
                            
                            match packet.action_id {
                                0 => {
                                    if allow_passthrough {
                                        let mut empty_session = S::default();
                                        let mut wsess = sessions.write().await;
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
                                        
                                        sessions.write().await.insert(ses_id.clone(), session);
                                        
                                        stream.write(return_packet.encode().as_slice()).await.unwrap();
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
                                        
                                        stream.write(return_packet.encode().as_slice()).await.unwrap();
                                    }
                                }
                                3 => {
                                    let passed_ses_id = &packet.session_id;
                                    
                                    let mut sessions = sessions.write().await;
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
                    };
                    
                }
            });
        }
    }
    
    
    
    pub fn passthrough(&mut self, allow: bool) {
        self.allow_passthrough = allow;
    }
    
    pub fn auth_handler(&mut self, handler: Box<dyn Fn(&str, &str) -> bool + Send + Sync>) {
        self.auth_handler = Arc::from(handler);
    }
    
    pub fn ok_handler(&mut self, handler: Box<dyn Fn(&mut S, P, &mut TcpStream) + Send + Sync>) {
        self.ok_handler = Arc::from(handler);
    }
    
}
