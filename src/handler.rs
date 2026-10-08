// Core query handling, shared by every protocol listener.
//
// Data flow: raw DNS query bytes -> parse -> blocked? NXDOMAIN
//            -> otherwise ask the upstream resolver (it caches) -> response bytes.

use crate::blocklist::Blocklist;
use hickory_resolver::TokioResolver;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
// portable-atomic (already pulled in by moka): mips32 has no native 64-bit atomics.
use portable_atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::Semaphore;

/// Upper bound on concurrent UDP queries plus open TCP/TLS/QUIC/HTTP connections.
/// Keeps memory bounded on small routers when flooded.
pub const MAX_INFLIGHT: usize = 512;

#[derive(Clone, Copy, PartialEq)]
pub enum Proto {
    Udp,
    Tcp,
    Dot,
    Doq,
    Doh,
}

#[derive(Default)]
pub struct Stats {
    udp: AtomicU64,
    tcp: AtomicU64,
    dot: AtomicU64,
    doq: AtomicU64,
    doh: AtomicU64,
    blocked: AtomicU64,
    servfail: AtomicU64,
}

pub struct Server {
    pub resolver: TokioResolver,
    pub blocklist: RwLock<Arc<Blocklist>>,
    pub stats: Stats,
    pub inflight: Arc<Semaphore>,
}

impl Server {
    pub fn new(resolver: TokioResolver) -> Server {
        Server {
            resolver,
            blocklist: RwLock::new(Arc::new(Blocklist::empty())),
            stats: Stats::default(),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
        }
    }

    pub fn current_blocklist(&self) -> Arc<Blocklist> {
        // The lock is only held for an Arc clone or swap, so it can't be poisoned
        // in practice (and panic = "abort" in release builds anyway).
        self.blocklist.read().expect("blocklist lock").clone()
    }

    pub fn set_blocklist(&self, list: Blocklist) {
        *self.blocklist.write().expect("blocklist lock") = Arc::new(list);
    }

    pub fn stats_json(&self) -> String {
        let s: &Stats = &self.stats;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let total: u64 = load(&s.udp) + load(&s.tcp) + load(&s.dot) + load(&s.doq) + load(&s.doh);
        format!(
            "{{\"queries\":{},\"udp\":{},\"tcp\":{},\"dot\":{},\"doq\":{},\"doh\":{},\"blocked\":{},\"servfail\":{},\"blocklist_entries\":{}}}\n",
            total,
            load(&s.udp),
            load(&s.tcp),
            load(&s.dot),
            load(&s.doq),
            load(&s.doh),
            load(&s.blocked),
            load(&s.servfail),
            self.current_blocklist().len()
        )
    }

    /// Answers one DNS query. Returns None only when the input is too short to
    /// even contain a message id, so there is nothing sensible to reply.
    pub async fn handle(&self, proto: Proto, request: &[u8]) -> Option<Vec<u8>> {
        let counter: &AtomicU64 = match proto {
            Proto::Udp => &self.stats.udp,
            Proto::Tcp => &self.stats.tcp,
            Proto::Dot => &self.stats.dot,
            Proto::Doq => &self.stats.doq,
            Proto::Doh => &self.stats.doh,
        };
        counter.fetch_add(1, Ordering::Relaxed);

        let query_msg: Message = match Message::from_vec(request) {
            Ok(message) => message,
            Err(_) => {
                if request.len() < 2 {
                    return None;
                }
                let id: u16 = u16::from_be_bytes([request[0], request[1]]);
                return Some(error_bytes(id, ResponseCode::FormErr));
            }
        };

        let mut response = Message::response(query_msg.id, query_msg.op_code);
        response.metadata.recursion_desired = query_msg.recursion_desired;
        response.metadata.recursion_available = true;
        if query_msg.edns.is_some() {
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            response.set_edns(edns);
        }

        if query_msg.message_type != MessageType::Query || query_msg.op_code != OpCode::Query {
            response.metadata.response_code = ResponseCode::NotImp;
            return Some(to_bytes(&response));
        }
        if query_msg.queries.len() != 1 {
            response.metadata.response_code = ResponseCode::FormErr;
            return Some(to_bytes(&response));
        }
        let query = query_msg.queries[0].clone();
        response.add_query(query.clone());

        let name_with_dot: String = query.name().to_lowercase().to_ascii();
        let name: &str = name_with_dot.trim_end_matches('.');
        if self.current_blocklist().is_blocked(name) {
            self.stats.blocked.fetch_add(1, Ordering::Relaxed);
            response.metadata.response_code = ResponseCode::NXDomain;
            return Some(to_bytes(&response));
        }

        match self
            .resolver
            .lookup(query.name().clone(), query.query_type())
            .await
        {
            Ok(lookup) => {
                response.add_answers(lookup.answers().iter().cloned());
            }
            // NXDOMAIN or "name exists but has no records of this type".
            Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
                response.metadata.response_code = no_records.response_code;
                if let Some(soa) = no_records.soa {
                    response.add_authority(soa.into_record_of_rdata());
                }
            }
            // Upstream answered with an error code such as REFUSED: pass it on.
            Err(NetError::Dns(DnsError::ResponseCode(code))) => {
                response.metadata.response_code = code;
            }
            Err(_) => {
                self.stats.servfail.fetch_add(1, Ordering::Relaxed);
                response.metadata.response_code = ResponseCode::ServFail;
            }
        }

        let mut bytes: Vec<u8> = to_bytes(&response);

        // UDP replies must fit the client's buffer; otherwise send an empty
        // reply with the TC flag so the client retries over TCP.
        if proto == Proto::Udp {
            let max_len: usize = match &query_msg.edns {
                Some(edns) => usize::from(edns.max_payload()).clamp(512, 1232),
                None => 512,
            };
            if bytes.len() > max_len {
                response.answers.clear();
                response.authorities.clear();
                response.additionals.clear();
                response.metadata.truncation = true;
                bytes = to_bytes(&response);
            }
        }
        Some(bytes)
    }
}

fn error_bytes(id: u16, code: ResponseCode) -> Vec<u8> {
    let message = Message::error_msg(id, OpCode::Query, code);
    // A header-only message always serializes; fall back to empty just in case.
    message.to_vec().unwrap_or_default()
}

fn to_bytes(response: &Message) -> Vec<u8> {
    match response.to_vec() {
        Ok(bytes) => bytes,
        Err(_) => error_bytes(response.id, ResponseCode::ServFail),
    }
}
