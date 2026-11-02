//! Contenedores de Docker y pods de Kubernetes: leer lo que listan `docker` y `kubectl` y
//! preparar la orden que abre una shell en ellos.

use serde::Deserialize;

/// Lo que se ejecuta dentro: bash si lo hay y, si no, sh, que tienen casi todas las imágenes.
pub const SHELL: &str = "if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    /// Como lo dice Docker, por ejemplo `Up 3 hours`.
    pub status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerLine {
    #[serde(rename = "ID")]
    id: String,
    names: String,
    image: String,
    #[serde(default)]
    status: String,
}

#[derive(Debug, thiserror::Error)]
#[error("la respuesta de {tool} no es la esperada: {source}")]
pub struct ParseError {
    tool: &'static str,
    source: serde_json::Error,
}

/// Los contenedores de `docker ps --format '{{json .}}'`: un objeto JSON por línea.
pub fn parse_docker_ps(text: &str) -> Result<Vec<Container>, ParseError> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|line| {
            let c: DockerLine = serde_json::from_str(line).map_err(|source| ParseError {
                tool: "docker",
                source,
            })?;
            Ok(Container {
                // Un contenedor con varios nombres los da separados por comas.
                name: c.names.split(',').next().unwrap_or_default().to_string(),
                id: c.id,
                image: c.image,
                status: c.status,
            })
        })
        .collect()
}

/// Lo que se pasa a `docker` para abrir una shell en el contenedor `id`.
pub fn docker_shell_args(id: &str) -> Vec<String> {
    ["exec", "-it", id, "sh", "-c", SHELL]
        .map(str::to_string)
        .to_vec()
}

/// Lo que se ejecuta en un servidor por SSH para listar sus contenedores. Pide solo los
/// campos que se usan (con `{{json .}}` las etiquetas de compose ocupan más de 1 KB por
/// contenedor) y los errores salen por la misma salida, para poder mostrarlos.
pub const DOCKER_PS_REMOTE: &str = "docker ps --no-trunc --format \
    '{\"ID\":{{json .ID}},\"Names\":{{json .Names}},\"Image\":{{json .Image}},\"Status\":{{json .Status}}}' 2>&1";

/// Un identificador de contenedor tal como lo da `docker ps --no-trunc`: solo hexadecimal,
/// así se puede poner en una orden del servidor sin comillas.
fn is_container_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// La orden que abre una shell en el contenedor `id` de un servidor por SSH; `None` si
/// el identificador no es uno de Docker.
pub fn docker_remote_shell(id: &str) -> Option<String> {
    is_container_id(id).then(|| format!("docker exec -it {id} sh -c '{SHELL}'"))
}

/// Qué decir cuando `docker ps` falla en un servidor, según lo que respondió.
pub fn docker_remote_error(output: &str, status: Option<u32>) -> String {
    let output = output.trim();
    if status == Some(127) || output.contains("command not found") {
        "Docker no está instalado en ese servidor".into()
    } else if output.contains("permission denied") {
        "tu usuario no puede usar Docker en ese servidor: añádelo al grupo docker \
         (sudo usermod -aG docker $USER) y vuelve a entrar"
            .into()
    } else {
        let first: String = output
            .lines()
            .next()
            .unwrap_or_default()
            .chars()
            .take(300)
            .collect();
        format!("docker falló en el servidor: {first}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pod {
    pub namespace: String,
    pub name: String,
    /// `Running`, `Pending`…
    pub phase: String,
    pub containers: Vec<String>,
}

#[derive(Deserialize)]
struct PodList {
    #[serde(default)]
    items: Vec<PodItem>,
}

#[derive(Deserialize)]
struct PodItem {
    metadata: PodMetadata,
    spec: Option<PodSpec>,
    status: Option<PodStatus>,
}

#[derive(Deserialize)]
struct PodMetadata {
    name: String,
    #[serde(default)]
    namespace: String,
}

#[derive(Deserialize)]
struct PodSpec {
    #[serde(default)]
    containers: Vec<PodContainer>,
}

#[derive(Deserialize)]
struct PodContainer {
    name: String,
}

#[derive(Deserialize)]
struct PodStatus {
    #[serde(default)]
    phase: String,
}

/// Los pods de `kubectl get pods --output json`, por espacio de nombres y nombre.
pub fn parse_pods(json: &str) -> Result<Vec<Pod>, ParseError> {
    let list: PodList = serde_json::from_str(json).map_err(|source| ParseError {
        tool: "kubectl",
        source,
    })?;
    let mut pods: Vec<Pod> = list
        .items
        .into_iter()
        .map(|item| Pod {
            namespace: item.metadata.namespace,
            name: item.metadata.name,
            phase: item.status.map(|s| s.phase).unwrap_or_default(),
            containers: item
                .spec
                .map(|s| s.containers.into_iter().map(|c| c.name).collect())
                .unwrap_or_default(),
        })
        .collect();
    pods.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    Ok(pods)
}

/// Los contextos de `kubectl config get-contexts --output name`.
pub fn parse_contexts(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Lo que se pasa a `kubectl` para abrir una shell en `container` del pod.
pub fn kubectl_shell_args(context: &str, pod: &Pod, container: &str) -> Vec<String> {
    [
        "exec",
        "-it",
        "--context",
        context,
        "--namespace",
        &pod.namespace,
        &pod.name,
        "--container",
        container,
        "--",
        "sh",
        "-c",
        SHELL,
    ]
    .map(str::to_string)
    .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_ps_lines_are_read() {
        let text = r#"{"Command":"\"nginx\"","ID":"3f2a9c01","Image":"nginx:1.27","Names":"web,alias","State":"running","Status":"Up 3 hours"}
{"ID":"77aa","Image":"postgres:16","Names":"db","Status":"Up 1 minute"}
"#;
        let containers = parse_docker_ps(text).unwrap();
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0].name, "web");
        assert_eq!(containers[0].image, "nginx:1.27");
        assert_eq!(containers[1].status, "Up 1 minute");
        assert!(parse_docker_ps("").unwrap().is_empty());
        assert!(parse_docker_ps("Cannot connect to the Docker daemon").is_err());
        assert_eq!(docker_shell_args("3f2a")[..3], ["exec", "-it", "3f2a"]);
    }

    #[test]
    fn the_remote_listing_asks_only_for_the_fields_it_reads() {
        // Lo que escribe `docker ps` con la plantilla de DOCKER_PS_REMOTE.
        let template = DOCKER_PS_REMOTE
            .split('\'')
            .nth(1)
            .expect("plantilla entre comillas simples");
        let line = template
            .replace("{{json .ID}}", r#""13c488e9b6ed""#)
            .replace("{{json .Names}}", r#""db-1""#)
            .replace("{{json .Image}}", r#""postgres:16""#)
            .replace("{{json .Status}}", r#""Up 6 days (healthy)""#);
        let containers = parse_docker_ps(&line).unwrap();
        assert_eq!(containers[0].id, "13c488e9b6ed");
        assert_eq!(containers[0].status, "Up 6 days (healthy)");
        assert!(DOCKER_PS_REMOTE.contains("--format '{"));
    }

    #[test]
    fn remote_commands_only_take_real_container_ids() {
        let id = "3f2a9c01".repeat(8);
        let command = docker_remote_shell(&id).unwrap();
        assert!(command.starts_with(&format!("docker exec -it {id} sh -c '")));
        assert!(!SHELL.contains('\''), "va entre comillas simples");
        assert_eq!(docker_remote_shell("web; rm -rf /"), None);
        assert_eq!(docker_remote_shell(""), None);
        assert!(
            docker_remote_error("bash: docker: command not found", Some(127))
                .contains("no está instalado")
        );
        assert!(
            docker_remote_error(
                "permission denied while trying to connect to the Docker daemon socket",
                Some(1)
            )
            .contains("grupo docker")
        );
    }

    #[test]
    fn pods_are_read_sorted_with_their_containers() {
        let json = r#"{"items": [
            {"metadata": {"name": "web-7d9", "namespace": "prod"},
             "spec": {"containers": [{"name": "web"}, {"name": "sidecar"}]},
             "status": {"phase": "Running"}},
            {"metadata": {"name": "api-1", "namespace": "dev"},
             "spec": {"containers": [{"name": "api"}]},
             "status": {"phase": "Pending"}}
        ]}"#;
        let pods = parse_pods(json).unwrap();
        assert_eq!(pods[0].name, "api-1");
        assert_eq!(pods[1].containers, ["web", "sidecar"]);
        assert_eq!(pods[1].phase, "Running");
        let args = kubectl_shell_args("kind", &pods[1], "sidecar");
        assert_eq!(
            args[..10],
            [
                "exec",
                "-it",
                "--context",
                "kind",
                "--namespace",
                "prod",
                "web-7d9",
                "--container",
                "sidecar",
                "--"
            ]
        );
        assert_eq!(parse_contexts("kind\n\nprod\n"), ["kind", "prod"]);
    }
}
