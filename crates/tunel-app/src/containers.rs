//! Contenedores de Docker y pods de Kubernetes de este equipo, con `docker` y `kubectl`
//! (ver `tunel_core::containers`).

use crate::tools;
use tunel_core::containers::{self, Container, Pod};
use tunel_term::local::CommandSpec;

fn missing(program: &str) -> String {
    match program {
        "docker" => "no se encontró «docker». Instala Docker Desktop o Docker Engine.".into(),
        _ => "no se encontró «kubectl». Instálalo y configura tus clústeres en ~/.kube/config."
            .into(),
    }
}

async fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let path = tools::find(program).ok_or_else(|| missing(program))?;
    tools::run_at(program, &path, args).await
}

/// Los contenedores en marcha.
pub async fn docker() -> Result<Vec<Container>, String> {
    let text = run("docker", &["ps", "--no-trunc", "--format", "{{json .}}"]).await?;
    containers::parse_docker_ps(&text).map_err(|e| e.to_string())
}

/// Los contextos de `kubectl` y cuál es el actual.
pub async fn contexts() -> Result<(Vec<String>, Option<String>), String> {
    let names = run("kubectl", &["config", "get-contexts", "--output", "name"]).await?;
    // Sin contexto actual, `kubectl` falla: no es un error para la lista.
    let current = run("kubectl", &["config", "current-context"])
        .await
        .ok()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty());
    Ok((containers::parse_contexts(&names), current))
}

/// Los pods de todos los espacios de nombres del contexto.
pub async fn pods(context: &str) -> Result<Vec<Pod>, String> {
    let args = [
        "get",
        "pods",
        "--all-namespaces",
        "--output",
        "json",
        "--context",
        context,
    ];
    containers::parse_pods(&run("kubectl", &args).await?).map_err(|e| e.to_string())
}

/// Lo que ejecuta la terminal para abrir la shell: `program` con `args`, encontrado
/// aunque la app no tenga el `PATH` de la terminal. Los complementos de autenticación de
/// `kubectl` (como los de AWS o Google) también necesitan ese `PATH`.
pub fn shell(program: &str, args: Vec<String>) -> Result<CommandSpec, String> {
    let path = tools::find(program).ok_or_else(|| missing(program))?;
    Ok(shell_at(&path, args))
}

fn shell_at(path: &std::path::Path, args: Vec<String>) -> CommandSpec {
    let search = std::env::join_paths(tools::search_path())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    CommandSpec {
        program: Some(path.to_string_lossy().into_owned()),
        args,
        env: vec![("PATH".into(), search)],
        cwd: None,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};
    use tunel_core::io::{SessionOutput, session_pair};

    /// Un `docker` falso: lista un contenedor y, al entrar, dice con qué argumentos.
    fn fake_docker(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("docker");
        std::fs::write(
            &path,
            "#!/bin/sh\n\
             if [ \"$1\" = ps ]; then\n\
               echo '{\"ID\":\"3f2a\",\"Names\":\"web\",\"Image\":\"nginx\",\"Status\":\"Up\"}'\n\
             else\n\
               echo \"dentro de $3 con $4\"\n\
             fi\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[tokio::test]
    async fn a_container_is_listed_and_its_shell_runs_in_a_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path());
        let text = tools::run_at("docker", &docker, &["ps", "--format", "{{json .}}"])
            .await
            .unwrap();
        let listed = containers::parse_docker_ps(&text).unwrap();
        assert_eq!(listed[0].name, "web");

        let spec = shell_at(&docker, containers::docker_shell_args(&listed[0].id));
        let (mut io, backend) = session_pair();
        tunel_term::local::spawn(&spec, 80, 24, backend).unwrap();
        let mut seen = String::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !seen.contains("dentro de 3f2a con sh") && Instant::now() < deadline {
            match io.output.try_recv() {
                Ok(SessionOutput::Data(bytes)) => seen.push_str(&String::from_utf8_lossy(&bytes)),
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        assert!(seen.contains("dentro de 3f2a con sh"), "{seen:?}");
    }
}
