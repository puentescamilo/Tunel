//! Cliente Telnet (RFC 854) con negociación de ECHO, SGA, TTYPE y NAWS.

use std::collections::HashSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tunel_core::io::{BackendIo, SessionInput, SessionOutput};

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;
const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;
const OPT_TTYPE: u8 = 24;
const OPT_NAWS: u8 = 31;
const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;
const TERMINAL_TYPE: &[u8] = b"XTERM-256COLOR";
const MAX_SUBNEGOTIATION: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Data,
    Iac,
    Command(u8),
    Sub,
    SubIac,
}

/// Separa datos y comandos Telnet; genera las respuestas de negociación.
pub struct TelnetParser {
    state: State,
    sub: Vec<u8>,
    answered: HashSet<(u8, u8)>,
    naws_enabled: bool,
    size: (u16, u16),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub data: Vec<u8>,
    pub reply: Vec<u8>,
}

fn naws_message(cols: u16, rows: u16) -> Vec<u8> {
    let mut payload = Vec::new();
    for byte in cols.to_be_bytes().into_iter().chain(rows.to_be_bytes()) {
        payload.push(byte);
        if byte == IAC {
            payload.push(IAC);
        }
    }
    [vec![IAC, SB, OPT_NAWS], payload, vec![IAC, SE]].concat()
}

impl TelnetParser {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            state: State::Data,
            sub: Vec::new(),
            answered: HashSet::new(),
            naws_enabled: false,
            size: (cols, rows),
        }
    }

    pub fn parse(&mut self, input: &[u8]) -> Parsed {
        let mut out = Parsed::default();
        for &byte in input {
            self.state = match (self.state, byte) {
                (State::Data, IAC) => State::Iac,
                (State::Data, b) => {
                    out.data.push(b);
                    State::Data
                }
                (State::Iac, IAC) => {
                    out.data.push(IAC);
                    State::Data
                }
                (State::Iac, cmd @ (DO | DONT | WILL | WONT)) => State::Command(cmd),
                (State::Iac, SB) => {
                    self.sub.clear();
                    State::Sub
                }
                (State::Iac, _) => State::Data,
                (State::Command(cmd), option) => {
                    out.reply.extend(self.negotiate(cmd, option));
                    State::Data
                }
                (State::Sub, IAC) => State::SubIac,
                (State::Sub, b) => {
                    if self.sub.len() < MAX_SUBNEGOTIATION {
                        self.sub.push(b);
                    }
                    State::Sub
                }
                (State::SubIac, SE) => {
                    out.reply.extend(self.subnegotiation());
                    State::Data
                }
                (State::SubIac, b) => {
                    if self.sub.len() < MAX_SUBNEGOTIATION {
                        self.sub.push(b);
                    }
                    State::Sub
                }
            };
        }
        out
    }

    fn negotiate(&mut self, cmd: u8, option: u8) -> Vec<u8> {
        let response = match cmd {
            WILL if matches!(option, OPT_ECHO | OPT_SGA) => DO,
            WILL => DONT,
            DO if matches!(option, OPT_TTYPE | OPT_NAWS) => WILL,
            DO => WONT,
            // DONT/WONT: aceptar en silencio para no entrar en bucles de negociación.
            _ => return Vec::new(),
        };
        // Responder una sola vez por petición, como recomienda RFC 1143.
        if !self.answered.insert((cmd, option)) {
            return Vec::new();
        }
        let mut reply = vec![IAC, response, option];
        if cmd == DO && option == OPT_NAWS {
            self.naws_enabled = true;
            reply.extend(naws_message(self.size.0, self.size.1));
        }
        reply
    }

    fn subnegotiation(&mut self) -> Vec<u8> {
        match self.sub.as_slice() {
            [OPT_TTYPE, TTYPE_SEND, ..] => [
                vec![IAC, SB, OPT_TTYPE, TTYPE_IS],
                TERMINAL_TYPE.to_vec(),
                vec![IAC, SE],
            ]
            .concat(),
            _ => Vec::new(),
        }
    }

    /// Mensaje NAWS para un cambio de tamaño, si el servidor lo aceptó.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Option<Vec<u8>> {
        self.size = (cols, rows);
        self.naws_enabled.then(|| naws_message(cols, rows))
    }
}

/// Escapa IAC y convierte CR solitario en CR NUL (NVT).
pub fn encode_outgoing(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (i, &b) in data.iter().enumerate() {
        match b {
            IAC => out.extend([IAC, IAC]),
            b'\r' if data.get(i + 1) != Some(&b'\n') => out.extend([b'\r', 0]),
            other => out.push(other),
        }
    }
    out
}

pub async fn run(
    host: &str,
    port: u16,
    cols: u16,
    rows: u16,
    io: BackendIo,
) -> std::io::Result<()> {
    let BackendIo { mut input, output } = io;
    let stream = TcpStream::connect((host, port)).await?;
    let (mut read_half, mut write_half) = stream.into_split();
    let mut parser = TelnetParser::new(cols, rows);
    let mut buf = vec![0u8; 8192];
    loop {
        tokio::select! {
            n = read_half.read(&mut buf) => {
                let n = n?;
                if n == 0 {
                    break;
                }
                let parsed = parser.parse(&buf[..n]);
                if !parsed.reply.is_empty() {
                    write_half.write_all(&parsed.reply).await?;
                }
                if !parsed.data.is_empty() && output.send(SessionOutput::Data(parsed.data)).is_err() {
                    break;
                }
            }
            cmd = input.recv() => match cmd {
                Some(SessionInput::Data(bytes)) => write_half.write_all(&encode_outgoing(&bytes)).await?,
                Some(SessionInput::Resize { cols, rows }) => {
                    if let Some(msg) = parser.resize(cols, rows) {
                        write_half.write_all(&msg).await?;
                    }
                }
                Some(SessionInput::Close) | None => break,
            },
        }
    }
    let _ = output.send(SessionOutput::Closed { exit_status: None });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_data_passes_through() {
        let mut p = TelnetParser::new(80, 24);
        assert_eq!(
            p.parse(b"login: "),
            Parsed {
                data: b"login: ".to_vec(),
                reply: vec![]
            }
        );
    }

    #[test]
    fn escaped_iac_becomes_data_byte() {
        let mut p = TelnetParser::new(80, 24);
        assert_eq!(p.parse(&[b'a', IAC, IAC, b'b']).data, vec![b'a', IAC, b'b']);
    }

    #[test]
    fn accepts_server_echo_and_sga() {
        let mut p = TelnetParser::new(80, 24);
        let out = p.parse(&[IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA]);
        assert_eq!(out.reply, vec![IAC, DO, OPT_ECHO, IAC, DO, OPT_SGA]);
        assert!(out.data.is_empty());
    }

    #[test]
    fn refuses_unknown_options() {
        let mut p = TelnetParser::new(80, 24);
        assert_eq!(p.parse(&[IAC, WILL, 99]).reply, vec![IAC, DONT, 99]);
        assert_eq!(p.parse(&[IAC, DO, 99]).reply, vec![IAC, WONT, 99]);
    }

    #[test]
    fn naws_reply_includes_window_size() {
        let mut p = TelnetParser::new(120, 40);
        let out = p.parse(&[IAC, DO, OPT_NAWS]);
        assert_eq!(
            out.reply,
            vec![
                IAC, WILL, OPT_NAWS, IAC, SB, OPT_NAWS, 0, 120, 0, 40, IAC, SE
            ]
        );
        assert_eq!(
            p.resize(100, 30),
            Some(vec![IAC, SB, OPT_NAWS, 0, 100, 0, 30, IAC, SE])
        );
    }

    #[test]
    fn resize_is_silent_until_naws_negotiated() {
        let mut p = TelnetParser::new(80, 24);
        assert_eq!(p.resize(100, 30), None);
    }

    #[test]
    fn naws_escapes_255_in_size() {
        assert_eq!(
            naws_message(255, 1),
            vec![IAC, SB, OPT_NAWS, 0, 255, 255, 0, 1, IAC, SE]
        );
    }

    #[test]
    fn terminal_type_request_is_answered() {
        let mut p = TelnetParser::new(80, 24);
        let out = p.parse(&[IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, SE]);
        assert_eq!(
            out.reply,
            [
                vec![IAC, SB, OPT_TTYPE, TTYPE_IS],
                TERMINAL_TYPE.to_vec(),
                vec![IAC, SE]
            ]
            .concat()
        );
    }

    #[test]
    fn repeated_requests_are_answered_once() {
        let mut p = TelnetParser::new(80, 24);
        p.parse(&[IAC, WILL, OPT_ECHO]);
        assert!(p.parse(&[IAC, WILL, OPT_ECHO]).reply.is_empty());
    }

    #[test]
    fn commands_split_across_reads_are_handled() {
        let mut p = TelnetParser::new(80, 24);
        assert!(p.parse(&[IAC]).reply.is_empty());
        assert_eq!(
            p.parse(&[WILL, OPT_SGA, b'x']),
            Parsed {
                data: vec![b'x'],
                reply: vec![IAC, DO, OPT_SGA]
            }
        );
    }

    #[test]
    fn outgoing_escapes_iac_and_lone_cr() {
        assert_eq!(encode_outgoing(&[b'a', IAC]), vec![b'a', IAC, IAC]);
        assert_eq!(encode_outgoing(b"ls\r"), b"ls\r\0".to_vec());
        assert_eq!(encode_outgoing(b"ls\r\n"), b"ls\r\n".to_vec());
    }
}
