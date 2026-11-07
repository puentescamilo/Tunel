use super::*;
use serde_json::{Value, json};

/// La clave de la organización de prueba: `testdata/clave-org-*.txt` la cifran con RSA.
fn org_key() -> SymmetricKey {
    SymmetricKey::from_bytes(&(0..64).collect::<Vec<u8>>()).unwrap()
}

fn seal(text: &str, key: &SymmetricKey) -> Value {
    Value::String(seal_text(text, key))
}

/// Una respuesta de `/api/sync` como la de Vaultwarden, cifrada con `user`.
fn sync_response(user: &SymmetricKey) -> SyncResponse {
    let org = org_key();
    let item_key = SymmetricKey::generate();
    let private_key = EncString::encrypt(user, include_bytes!("../testdata/rsa-prueba.der"));
    let mut broken = seal_text("x", user);
    broken.replace_range(broken.len() - 4.., "AAA=");
    serde_json::from_value(json!({
        "object": "sync",
        "profile": {
            "id": "usuario-1",
            "privateKey": private_key.to_string(),
            "organizations": [
                { "id": "org-1", "name": "Gamma", "key": include_str!("../testdata/clave-org-sha1.txt").trim() },
                { "id": "org-mala", "name": "Otra", "key": "4.AAAA" },
            ],
        },
        "collections": [
            { "id": "col-1", "organizationId": "org-1", "name": seal("Clientes/ACME/Switches", &org), "hidePasswords": true, "readOnly": true },
            { "id": "col-2", "organizationId": "org-mala", "name": "2.AAAA|AAAA|AAAA" },
        ],
        "ciphers": [
            {
                "id": "personal", "type": 1, "organizationId": null, "name": seal("Mi servidor", user),
                "notes": seal("rack 3", user),
                "login": {
                    "username": seal("camilo", user), "password": seal("s3creta", user),
                    "uris": [{ "uri": seal("ssh://10.0.0.5:22", user), "match": null }],
                },
                "fields": [{ "type": 1, "name": seal("enable", user), "value": seal("en4ble", user) }],
                "collectionIds": [], "viewPassword": true, "deletedDate": null,
            },
            {
                "id": "switch", "type": 1, "organizationId": "org-1", "name": seal("SW-Core", &item_key),
                "key": seal_text_bytes(&item_key, &org),
                "login": { "username": seal("admin", &item_key), "password": seal("cisco", &item_key) },
                "collectionIds": ["col-1"], "viewPassword": false,
            },
            {
                "id": "clave", "type": 5, "organizationId": null, "name": seal("Clave deploy", user),
                "sshKey": {
                    "privateKey": seal("-----BEGIN OPENSSH PRIVATE KEY-----", user),
                    "publicKey": seal("ssh-ed25519 AAAA", user),
                    "keyFingerprint": seal("SHA256:abc", user),
                },
            },
            { "id": "borrado", "type": 1, "name": seal("viejo", user), "deletedDate": "2026-01-01T00:00:00Z" },
            { "id": "tarjeta", "type": 3, "name": seal("Visa", user) },
            { "id": "roto", "type": 1, "name": broken },
            { "id": "de-org-mala", "type": 1, "organizationId": "org-mala", "name": "2.AAAA|AAAA|AAAA" },
        ],
        "policies": [
            { "type": 5, "enabled": true, "organizationId": "org-1" },
            { "type": 1, "enabled": true, "organizationId": "org-1" },
        ],
    }))
    .unwrap()
}

fn seal_text_bytes(inner: &SymmetricKey, outer: &SymmetricKey) -> String {
    EncString::encrypt(outer, &inner.to_bytes()).to_string()
}

#[test]
fn a_synced_vault_opens_with_the_user_key() {
    let user = SymmetricKey::generate();
    let vault = Vault::open(&sync_response(&user), &user).unwrap();

    assert_eq!(
        vault.organizations,
        [Organization {
            id: "org-1".into(),
            name: "Gamma".into()
        }]
    );
    assert_eq!(vault.collections.len(), 1);
    assert_eq!(vault.collections[0].name, "Clientes/ACME/Switches");
    assert!(vault.collections[0].hide_passwords);
    assert!(vault.collections[0].read_only);
    assert!(vault.personal_vault_disabled);

    let personal = vault.item("personal").unwrap();
    assert_eq!(personal.name, "Mi servidor");
    assert_eq!(personal.notes.as_deref(), Some("rack 3"));
    assert_eq!(
        personal.content,
        Content::Login {
            username: Some("camilo".into()),
            password: Some("s3creta".into()),
            uris: vec!["ssh://10.0.0.5:22".into()],
        }
    );
    let enable = personal.field("ENABLE").unwrap();
    assert!(enable.hidden && enable.value == "en4ble");
}

#[test]
fn organization_items_and_items_with_their_own_key_open_too() {
    let user = SymmetricKey::generate();
    let vault = Vault::open(&sync_response(&user), &user).unwrap();
    let switch = vault.item("switch").unwrap();
    assert_eq!(switch.name, "SW-Core");
    assert_eq!(switch.organization_id.as_deref(), Some("org-1"));
    assert_eq!(switch.collection_ids, ["col-1"]);
    assert!(!switch.view_password);
    assert!(matches!(&switch.content, Content::Login { password: Some(p), .. } if p == "cisco"));

    let key = vault.item("clave").unwrap();
    assert!(
        matches!(&key.content, Content::SshKey { private_key, fingerprint: Some(f), .. }
        if private_key.starts_with("-----BEGIN") && f == "SHA256:abc")
    );
}

#[test]
fn deleted_and_unrelated_items_are_left_out_and_broken_ones_are_reported() {
    let user = SymmetricKey::generate();
    let vault = Vault::open(&sync_response(&user), &user).unwrap();
    let ids: Vec<&str> = vault.items.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids, ["personal", "switch", "clave"]);
    let unreadable: Vec<&str> = vault.unreadable.iter().map(|u| u.id.as_str()).collect();
    assert_eq!(unreadable, ["org-mala", "roto"]);
    assert_eq!(vault.unreadable[1].reason, CryptoError::Mac);
}

#[test]
fn another_user_key_cannot_open_the_vault() {
    let user = SymmetricKey::generate();
    let other = SymmetricKey::generate();
    assert!(matches!(
        Vault::open(&sync_response(&user), &other),
        Err(VwError::Crypto(CryptoError::Mac))
    ));
}

#[test]
fn a_new_login_is_sealed_with_the_key_of_where_it_goes() {
    let user = SymmetricKey::generate();
    let vault = Vault::open(&sync_response(&user), &user).unwrap();
    let new = NewLogin {
        name: "AP-Piso2".into(),
        username: Some("ubnt".into()),
        password: Some("clave".into()),
        uris: vec!["ssh://10.0.2.1".into()],
        notes: None,
        fields: vec![Field {
            name: "enable".into(),
            value: "x".into(),
            hidden: true,
        }],
    };
    let org = vault.key_for(Some("org-1"), &user).unwrap();
    assert_eq!(vault.user_id, "usuario-1");
    let mut sealed = new.seal(org, Some("org-1"), &vault.user_id);
    sealed.id = "nuevo".into();
    let item = open_item(&sealed, &org_key()).unwrap();
    assert_eq!(item.name, "AP-Piso2");
    assert_eq!(item.field("enable").unwrap().value, "x");
    assert!(matches!(&item.content, Content::Login { uris, .. } if uris == &["ssh://10.0.2.1"]));
    assert!(
        open_item(&sealed, &user).is_err(),
        "no va con la clave personal"
    );
    assert!(vault.key_for(Some("org-desconocida"), &user).is_none());

    let body = serde_json::to_value(&sealed).unwrap();
    assert_eq!(body["type"], 1);
    assert_eq!(body["organizationId"], "org-1");
    assert_eq!(
        body["encryptedFor"], "usuario-1",
        "Vaultwarden rechaza (422) lo que no dice quién lo cifró"
    );
    assert!(body.get("id").is_none() && body.get("deletedDate").is_none());
    assert!(
        !body.to_string().contains("AP-Piso2"),
        "nada viaja sin cifrar"
    );
}

#[test]
fn debug_output_does_not_show_secrets() {
    let user = SymmetricKey::generate();
    let vault = Vault::open(&sync_response(&user), &user).unwrap();
    let text = format!("{:?}", vault.item("personal").unwrap());
    assert!(
        !text.contains("s3creta") && !text.contains("Mi servidor"),
        "{text}"
    );
}

#[test]
fn without_the_policy_the_personal_vault_is_allowed() {
    let user = SymmetricKey::generate();
    let mut sync = sync_response(&user);
    sync.policies
        .retain(|p| p.kind != wire::PERSONAL_OWNERSHIP_POLICY);
    assert!(!Vault::open(&sync, &user).unwrap().personal_vault_disabled);
    sync.policies.clear();
    assert!(!Vault::open(&sync, &user).unwrap().personal_vault_disabled);
}
