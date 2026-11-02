//! Servidor SSH mínimo para las pruebas de SFTP y Mosh: entra con contraseña, sirve SFTP sobre
//! una carpeta temporal y responde a `exec` con salidas fijas.

#![allow(dead_code)]

use russh::keys::decode_secret_key;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tunel_core::*;
use tunel_ssh::{ConnectContext, Interaction, SshConnection};

pub const USER: &str = "ana";
pub const PASSWORD: &str = "contraseña-correcta";
const HOST_KEY: &str = include_str!("../fixtures/host_ed25519");
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// Lo que responde el servidor a cada orden de `exec`: salida y código de salida.
pub type Commands = HashMap<String, (String, u32)>;

#[derive(Clone)]
struct TestServer {
    root: PathBuf,
    commands: Arc<Commands>,
    /// Canales abiertos que aún no pidieron subsistema ni orden.
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    /// Órdenes que llegaron por `exec`, en orden.
    executed: Arc<Mutex<Vec<String>>>,
}

impl server::Server for TestServer {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == USER && password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().unwrap().insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let channel = self.channels.lock().unwrap().remove(&id);
        match channel {
            Some(channel) if name == "sftp" => {
                session.channel_success(id)?;
                let sftp = Sftp {
                    root: self.root.clone(),
                    ..Sftp::default()
                };
                tokio::spawn(russh_sftp::server::run(channel.into_stream(), sftp));
            }
            _ => session.channel_failure(id)?,
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        self.executed.lock().unwrap().push(command.clone());
        let (output, status) = self
            .commands
            .get(&command)
            .cloned()
            .unwrap_or_else(|| (format!("sh: {command}: not found\n"), 127));
        session.channel_success(id)?;
        session.data(id, output.into_bytes())?;
        // Como OpenSSH: el estado llega después del EOF.
        session.eof(id)?;
        session.exit_status_request(id, status)?;
        session.close(id)?;
        Ok(())
    }
}

/// Servidor SFTP sobre `root`: las rutas absolutas del cliente cuelgan de ahí.
#[derive(Default)]
struct Sftp {
    root: PathBuf,
    files: HashMap<String, std::fs::File>,
    /// Carpetas abiertas y si ya se listaron.
    dirs: HashMap<String, bool>,
    next: u64,
}

fn status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

fn io_error(e: std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

impl Sftp {
    /// La ruta local de `path`; nada sale de `root`.
    fn local(&self, path: &str) -> Result<PathBuf, StatusCode> {
        let relative = Path::new(path.trim_start_matches('/'));
        if relative
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_) | std::path::Component::CurDir))
        {
            return Err(StatusCode::PermissionDenied);
        }
        Ok(self.root.join(relative))
    }

    fn handle(&mut self) -> String {
        self.next += 1;
        self.next.to_string()
    }
}

impl russh_sftp::server::Handler for Sftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _: u32, _: HashMap<String, String>) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let path = if path == "." { "/".to_string() } else { path };
        Ok(Name {
            id,
            files: vec![File::dummy(path)],
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let file = std::fs::OpenOptions::new()
            .read(flags.contains(OpenFlags::READ))
            .write(flags.contains(OpenFlags::WRITE))
            .create(flags.contains(OpenFlags::CREATE))
            .truncate(flags.contains(OpenFlags::TRUNCATE))
            .open(self.local(&filename)?)
            .map_err(io_error)?;
        let handle = self.handle();
        self.files.insert(handle.clone(), file);
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        use std::io::{Read, Seek, SeekFrom};
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
        let mut data = vec![0; len as usize];
        let n = file.read(&mut data).map_err(io_error)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        data.truncate(n);
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        use std::io::{Seek, SeekFrom, Write};
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
        file.write_all(&data).map_err(io_error)?;
        Ok(status(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.files.remove(&handle);
        self.dirs.remove(&handle);
        Ok(status(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        if !self.local(&path)?.is_dir() {
            return Err(StatusCode::NoSuchFile);
        }
        self.dirs.insert(path.clone(), false);
        Ok(Handle { id, handle: path })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let listed = self.dirs.get_mut(&handle).ok_or(StatusCode::Failure)?;
        if std::mem::replace(listed, true) {
            return Err(StatusCode::Eof);
        }
        let mut files = Vec::new();
        for entry in std::fs::read_dir(self.local(&handle)?).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let meta = entry.metadata().map_err(io_error)?;
            files.push(File::new(
                entry.file_name().to_string_lossy(),
                FileAttributes::from(&meta),
            ));
        }
        Ok(Name { id, files })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = std::fs::metadata(self.local(&path)?).map_err(io_error)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&meta),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn mkdir(&mut self, id: u32, path: String, _: FileAttributes) -> Result<Status, Self::Error> {
        std::fs::create_dir(self.local(&path)?).map_err(io_error)?;
        Ok(status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        std::fs::remove_dir(self.local(&path)?).map_err(io_error)?;
        Ok(status(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        std::fs::remove_file(self.local(&filename)?).map_err(io_error)?;
        Ok(status(id))
    }

    async fn rename(&mut self, id: u32, from: String, to: String) -> Result<Status, Self::Error> {
        std::fs::rename(self.local(&from)?, self.local(&to)?).map_err(io_error)?;
        Ok(status(id))
    }
}

/// Un servidor en marcha: su puerto, su carpeta y las órdenes que recibió.
pub struct Running {
    pub port: u16,
    pub root: tempfile::TempDir,
    executed: Arc<Mutex<Vec<String>>>,
}

impl Running {
    pub fn executed(&self) -> Vec<String> {
        self.executed.lock().unwrap().clone()
    }
}

pub async fn start(commands: Commands) -> Running {
    let config = Arc::new(server::Config {
        keys: vec![decode_secret_key(HOST_KEY, None).unwrap()],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = tempfile::tempdir().unwrap();
    let executed = Arc::<Mutex<Vec<String>>>::default();
    let mut server = TestServer {
        root: root.path().to_path_buf(),
        commands: Arc::new(commands),
        channels: Arc::default(),
        executed: executed.clone(),
    };
    tokio::spawn(async move {
        let _ = server.run_on_socket(config, &listener).await;
    });
    Running {
        port,
        root,
        executed,
    }
}

/// Se conecta como `ana`, aceptando la clave del servidor.
pub async fn connect(port: u16) -> SshConnection {
    let identity = Identity::new("ana", USER).with_password(PASSWORD);
    let host = Host {
        port: Some(port),
        identity: Some(identity.id),
        ..Host::new("prueba", "127.0.0.1")
    };
    let id = host.id;
    let vault = VaultData::default().with_identity(identity).with_host(host);
    let (interactions, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(interaction) = rx.recv().await {
            if let Interaction::HostKey { reply, .. } = interaction {
                let _ = reply.send(true);
            }
        }
    });
    let snapshot = vault.clone();
    let context = ConnectContext {
        lookup: Arc::new(move |h, p, a, f| snapshot.check_host_key(h, p, a, f)),
        interactions,
        keepalive: None,
        security_key: None,
    };
    let target = vault.resolve(id).unwrap();
    tokio::time::timeout(TIMEOUT, SshConnection::connect(&context, &[], &target))
        .await
        .expect("la conexión no terminó a tiempo")
        .expect("no se pudo conectar")
}
