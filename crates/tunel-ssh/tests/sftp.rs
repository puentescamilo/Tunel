//! SFTP de punta a punta contra un servidor `russh-sftp` sobre una carpeta temporal.

mod support;

use tunel_ssh::sftp::SftpClient;

async fn client(server: &support::Running) -> (tunel_ssh::SshConnection, SftpClient) {
    let conn = support::connect(server.port).await;
    let sftp = SftpClient::open(&conn).await.expect("se abre SFTP");
    (conn, sftp)
}

#[tokio::test]
async fn lists_folders_first_and_skips_dot_entries() {
    let server = support::start(Default::default()).await;
    std::fs::write(server.root.path().join("b.txt"), "b").unwrap();
    std::fs::write(server.root.path().join("a.txt"), "aa").unwrap();
    std::fs::create_dir(server.root.path().join("z-carpeta")).unwrap();
    let (_conn, sftp) = client(&server).await;

    let home = sftp.home().await.unwrap();
    assert_eq!(home, "/");
    let entries = sftp.list(&home).await.unwrap();
    let names: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.is_dir)).collect();
    assert_eq!(names, [("z-carpeta", true), ("a.txt", false), ("b.txt", false)]);
    assert_eq!(entries[1].size, 2);
}

#[tokio::test]
async fn uploads_and_downloads_a_file_larger_than_one_chunk() {
    let server = support::start(Default::default()).await;
    let (_conn, sftp) = client(&server).await;
    let local = tempfile::tempdir().unwrap();
    // Más que un bloque de copia, y bytes que no son texto.
    let content: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let source = local.path().join("origen.bin");
    std::fs::write(&source, &content).unwrap();

    let mut seen = Vec::new();
    let sent = sftp
        .upload(&source, "/subido.bin", |n| seen.push(n))
        .await
        .unwrap();
    assert_eq!(sent, content.len() as u64);
    assert_eq!(seen.last(), Some(&sent));
    assert!(seen.windows(2).all(|w| w[0] < w[1]), "el progreso solo avanza");
    assert_eq!(std::fs::read(server.root.path().join("subido.bin")).unwrap(), content);

    let target = local.path().join("bajado.bin");
    let received = sftp.download("/subido.bin", &target, |_| {}).await.unwrap();
    assert_eq!(received, content.len() as u64);
    assert_eq!(std::fs::read(&target).unwrap(), content);
}

#[tokio::test]
async fn creates_renames_and_removes_files_and_folders() {
    let server = support::start(Default::default()).await;
    let (_conn, sftp) = client(&server).await;
    let root = server.root.path();

    sftp.mkdir("/nueva").await.unwrap();
    assert!(root.join("nueva").is_dir());
    std::fs::write(root.join("nueva/nota.txt"), "hola").unwrap();
    sftp.rename("/nueva/nota.txt", "/nueva/renombrada.txt").await.unwrap();
    assert!(root.join("nueva/renombrada.txt").is_file());
    assert!(!root.join("nueva/nota.txt").exists());

    // Una carpeta con algo dentro no se borra.
    assert!(sftp.remove("/nueva", true).await.is_err());
    sftp.remove("/nueva/renombrada.txt", false).await.unwrap();
    sftp.remove("/nueva", true).await.unwrap();
    assert!(!root.join("nueva").exists());
}

#[tokio::test]
async fn a_missing_path_is_an_error_not_an_empty_folder() {
    let server = support::start(Default::default()).await;
    let (_conn, sftp) = client(&server).await;
    assert!(sftp.list("/no-existe").await.is_err());
    let local = tempfile::tempdir().unwrap();
    assert!(
        sftp.download("/no-existe.txt", &local.path().join("x"), |_| {})
            .await
            .is_err()
    );
}
