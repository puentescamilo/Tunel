//! En Windows incrusta el icono y los datos de versión en el ejecutable.

fn main() {
    println!("cargo:rerun-if-changed=assets/icons/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut resource = winresource::WindowsResource::new();
    resource
        .set_icon("assets/icons/icon.ico")
        .set("ProductName", "Túnel")
        .set("FileDescription", "Túnel")
        .set("LegalCopyright", "Camilo Puentes · GPLv3");
    if let Err(err) = resource.compile() {
        panic!("no se pudo incrustar el icono de Windows: {err}");
    }
}
