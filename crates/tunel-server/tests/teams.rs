//! Pruebas de los equipos con el cifrado real: la clave del equipo pasa de un
//! administrador a los miembros sin que el servidor pueda abrirla, y al sacar a alguien
//! se renueva.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use tunel_core::crypto::KdfParams;
use tunel_core::model::Host;
use tunel_core::sync::protocol::*;
use tunel_core::sync::team::{open_team_name, seal_team_name, unwrap_team_key, wrap_team_key};
use tunel_core::sync::{
    AccountKeypair, AccountKeys, Manifest, PublicKey, SyncState, TeamKeyContext, VaultKey,
};
use tunel_core::vault::VaultData;
use tunel_server::admin::{AdminError, Command, run};
use tunel_server::auth::StoredHash;
use tunel_server::db::NewAccount;
use tunel_server::{AppState, Config, Db, router};
use uuid::Uuid;

const SALT: &[u8; 16] = b"sal-de-la-cuenta";
const TEAM: &str = "6c2b8f0e-6f4e-4d55-9a37-1e2f3a4b5c6d";

async fn app() -> Router {
    app_on(Db::open_in_memory().unwrap()).await
}

/// Servidor sobre `db`, para usar también los comandos de administración.
async fn app_on(db: Db) -> Router {
    let config = Config {
        open_registration: true,
        auth_kdf: KdfParams::FAST_FOR_TESTS,
        unauthenticated_burst: 1000,
        ..Config::default()
    };
    let state = AppState::new(db, config).await.unwrap();
    router(state)
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Una cuenta con sesión iniciada y su par de claves subido.
struct User {
    token: String,
    keys: AccountKeypair,
}

impl User {
    fn token(&self) -> Option<&str> {
        Some(&self.token)
    }

    fn public(&self) -> PublicKey {
        self.keys.public()
    }
}

fn account(email: &str) -> AccountKeys {
    AccountKeys::derive_for_tests(email.as_bytes(), SALT)
}

async fn login(app: &Router, email: &str) -> LoginResponse {
    let body = json!({"email": email, "auth": account(email).auth_token().as_str()});
    let (status, body) = send(app, "POST", "/v1/sessions", None, Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_value(body).unwrap()
}

/// Crea la cuenta sin claves, como una creada antes de los equipos.
async fn register_without_keys(app: &Router, email: &str) -> String {
    let keys = account(email);
    let body = serde_json::to_value(RegisterRequest {
        email: email.into(),
        kdf: KdfParams::RECOMMENDED,
        salt: B64.encode(SALT),
        auth: keys.auth_token().to_string(),
        vault_key: VaultKey::generate().wrap(&keys).unwrap(),
    })
    .unwrap();
    let (status, body) = send(app, "POST", "/v1/accounts", None, Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    login(app, email).await.token
}

async fn user(app: &Router, email: &str) -> User {
    let token = register_without_keys(app, email).await;
    let keys = AccountKeypair::generate();
    let body = serde_json::to_value(AccountKeysBlob {
        public_key: keys.public(),
        private_key: keys.seal(&VaultKey::generate()).unwrap(),
    })
    .unwrap();
    let (status, body) = send(app, "PUT", "/v1/keys", Some(&token), Some(body)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    User { token, keys }
}

fn context(epoch: u64) -> TeamKeyContext<'static> {
    TeamKeyContext { team: TEAM, epoch }
}

async fn create_team(app: &Router, admin: &User, name: &str) -> VaultKey {
    let key = VaultKey::generate();
    let body = serde_json::to_value(CreateTeamRequest {
        roster: None,
        id: TEAM.into(),
        name: seal_team_name(&key, TEAM, name).unwrap(),
        key: wrap_team_key(&key, context(0), &admin.keys, &admin.public()).unwrap(),
    })
    .unwrap();
    let (status, body) = send(app, "POST", "/v1/teams", admin.token(), Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    key
}

/// El administrador pide la clave pública del invitado al servidor y le envuelve la del
/// equipo.
async fn invite(app: &Router, admin: &User, email: &str, key: &VaultKey, epoch: u64) -> StatusCode {
    let (status, body) = send(
        app,
        "GET",
        &format!("/v1/users/{email}/key"),
        admin.token(),
        None,
    )
    .await;
    if status != StatusCode::OK {
        return status;
    }
    let found: UserKeyResponse = serde_json::from_value(body).unwrap();
    let body = serde_json::to_value(AddMemberRequest {
        email: email.into(),
        role: TeamRole::Member,
        epoch,
        key: wrap_team_key(key, context(epoch), &admin.keys, &found.public_key).unwrap(),
    })
    .unwrap();
    let uri = format!("/v1/teams/{TEAM}/members");
    send(app, "POST", &uri, admin.token(), Some(body)).await.0
}

async fn accept(app: &Router, user: &User) -> StatusCode {
    let uri = format!("/v1/teams/{TEAM}/accept");
    send(app, "POST", &uri, user.token(), None).await.0
}

/// Invita y acepta.
async fn join(app: &Router, admin: &User, member: &User, email: &str, key: &VaultKey) {
    assert_eq!(invite(app, admin, email, key, 0).await, StatusCode::CREATED);
    assert_eq!(accept(app, member).await, StatusCode::NO_CONTENT);
}

async fn teams(app: &Router, user: &User) -> Vec<TeamSummary> {
    let (status, body) = send(app, "GET", "/v1/teams", user.token(), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_value(body).unwrap()
}

/// Recupera la clave del equipo como haría el cliente, comprobando quién la envolvió.
fn open_key(user: &User, team: &TeamSummary) -> VaultKey {
    unwrap_team_key(
        team.key.as_ref().unwrap(),
        context(team.epoch),
        &user.keys,
        &team.wrapped_by_key,
    )
    .unwrap()
}

fn host(name: &str) -> Host {
    Host {
        label: name.into(),
        address: format!("{name}.ejemplo.com"),
        ..Host::default()
    }
}

/// Sube a la bóveda del equipo los cambios de `data` sobre el manifiesto `base`.
async fn push_team(
    app: &Router,
    user: &User,
    key: &VaultKey,
    epoch: u64,
    data: &VaultData,
    base: &Manifest,
) -> (StatusCode, Manifest) {
    let state = SyncState::adopt(Uuid::new_v4(), data, 1000).unwrap();
    let outgoing = state.outgoing(data).unwrap();
    let manifest = base.with_pushed(outgoing.iter().map(|e| (key.record_id(&e.key), e.hlc)));
    let request = PushRequest {
        epoch: Some(epoch),
        base_version: base.version,
        manifest: ManifestBlob {
            version: manifest.version,
            blob: manifest.seal(key).unwrap(),
        },
        records: outgoing
            .iter()
            .map(|e| key.seal_record(e).unwrap())
            .collect(),
    };
    let uri = format!("/v1/teams/{TEAM}/records");
    let body = serde_json::to_value(request).unwrap();
    (
        send(app, "POST", &uri, user.token(), Some(body)).await.0,
        manifest,
    )
}

async fn pull_team(app: &Router, user: &User) -> (StatusCode, Value) {
    let uri = format!("/v1/teams/{TEAM}/records?since=0");
    send(app, "GET", &uri, user.token(), None).await
}

fn hostnames(key: &VaultKey, page: &PullResponse) -> Vec<String> {
    page.records
        .iter()
        .filter_map(|r| key.open_record(r).unwrap().value)
        .map(|v| v["address"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn a_member_downloads_what_the_admin_shares() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let key = create_team(&app, &ana, "Infraestructura").await;
    join(&app, &ana, &bob, "bob@ejemplo.com", &key).await;

    let data = VaultData {
        hosts: vec![host("web")],
        ..VaultData::default()
    };
    let (status, _) = push_team(&app, &ana, &key, 0, &data, &Manifest::empty()).await;
    assert_eq!(status, StatusCode::OK);

    let summary = teams(&app, &bob).await.remove(0);
    assert_eq!(summary.role, TeamRole::Member);
    assert_eq!(summary.wrapped_by, "ana@ejemplo.com");
    assert_eq!(summary.wrapped_by_key, ana.public());
    let bob_key = open_key(&bob, &summary);
    assert_eq!(
        open_team_name(&bob_key, TEAM, summary.name.as_ref().unwrap()).unwrap(),
        "Infraestructura"
    );

    let (status, body) = pull_team(&app, &bob).await;
    assert_eq!(status, StatusCode::OK);
    let page: PullResponse = serde_json::from_value(body).unwrap();
    assert_eq!(page.epoch, Some(0));
    assert_eq!(hostnames(&bob_key, &page), ["web.ejemplo.com"]);
    let blob = page.manifest.as_ref().unwrap();
    let manifest = Manifest::open(&blob.blob, blob.version, &bob_key).unwrap();
    assert_eq!(manifest.version, 1);
}

#[tokio::test]
async fn outsiders_see_nothing_and_members_cannot_manage_the_team() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let eve = user(&app, "eve@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    join(&app, &ana, &bob, "bob@ejemplo.com", &key).await;

    // A quien no es miembro se le responde como si el equipo no existiera.
    assert_eq!(pull_team(&app, &eve).await.0, StatusCode::NOT_FOUND);
    let members = format!("/v1/teams/{TEAM}/members");
    assert_eq!(
        send(&app, "GET", &members, eve.token(), None).await.0,
        StatusCode::NOT_FOUND
    );
    assert!(teams(&app, &eve).await.is_empty());
    let (status, _) = push_team(
        &app,
        &eve,
        &key,
        0,
        &VaultData::default(),
        &Manifest::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Un miembro no puede invitar, cambiar roles, sacar a otros ni borrar el equipo.
    assert_eq!(
        invite(&app, &bob, "eve@ejemplo.com", &key, 0).await,
        StatusCode::FORBIDDEN
    );
    let ana_uri = format!("/v1/teams/{TEAM}/members/ana@ejemplo.com");
    let demote = json!({"role": "member"});
    let (status, _) = send(&app, "PATCH", &ana_uri, bob.token(), Some(demote)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        send(&app, "DELETE", &ana_uri, bob.token(), None).await.0,
        StatusCode::FORBIDDEN
    );
    let team_uri = format!("/v1/teams/{TEAM}");
    assert_eq!(
        send(&app, "DELETE", &team_uri, bob.token(), None).await.0,
        StatusCode::FORBIDDEN
    );

    // Sin sesión, nada.
    assert_eq!(
        send(&app, "GET", "/v1/teams", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_key_pair_is_uploaded_once_and_any_device_can_fetch_it() {
    let app = app().await;
    let token = register_without_keys(&app, "ana@ejemplo.com").await;
    let (status, _) = send(&app, "GET", "/v1/keys", Some(&token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let vault = VaultKey::generate();
    let pair = AccountKeypair::generate();
    let upload = |pair: &AccountKeypair| {
        serde_json::to_value(AccountKeysBlob {
            public_key: pair.public(),
            private_key: pair.seal(&vault).unwrap(),
        })
        .unwrap()
    };
    let (status, _) = send(&app, "PUT", "/v1/keys", Some(&token), Some(upload(&pair))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Otro equipo que llega tarde no puede sustituirlo.
    let late = AccountKeypair::generate();
    let (status, _) = send(&app, "PUT", "/v1/keys", Some(&token), Some(upload(&late))).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, body) = send(&app, "GET", "/v1/keys", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let keys: AccountKeysBlob = serde_json::from_value(body).unwrap();
    let opened = AccountKeypair::open(&keys.private_key, &keys.public_key, &vault).unwrap();
    assert_eq!(opened.public(), pair.public());
}

#[tokio::test]
async fn only_accounts_with_keys_can_be_invited() {
    // Sin claves o sin cuenta, la respuesta es la misma.
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    register_without_keys(&app, "old@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    assert_eq!(
        invite(&app, &ana, "old@ejemplo.com", &key, 0).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        invite(&app, &ana, "nadie@ejemplo.com", &key, 0).await,
        StatusCode::NOT_FOUND
    );

    // Ni crear equipos sin claves.
    let token = register_without_keys(&app, "sin@ejemplo.com").await;
    let body = serde_json::to_value(CreateTeamRequest {
        roster: None,
        id: Uuid::new_v4().to_string(),
        name: seal_team_name(&key, TEAM, "x").unwrap(),
        key: wrap_team_key(&key, context(0), &ana.keys, &ana.public()).unwrap(),
    })
    .unwrap();
    let (status, _) = send(&app, "POST", "/v1/teams", Some(&token), Some(body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn invitations_reject_stale_epochs_and_duplicates() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    user(&app, "bob@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    assert_eq!(
        invite(&app, &ana, "bob@ejemplo.com", &key, 1).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        invite(&app, &ana, "bob@ejemplo.com", &key, 0).await,
        StatusCode::CREATED
    );
    assert_eq!(
        invite(&app, &ana, "bob@ejemplo.com", &key, 0).await,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn the_team_never_runs_out_of_admins() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    join(&app, &ana, &bob, "bob@ejemplo.com", &key).await;

    let ana_uri = format!("/v1/teams/{TEAM}/members/ana@ejemplo.com");
    let demote = json!({"role": "member"});
    let (status, _) = send(&app, "PATCH", &ana_uri, ana.token(), Some(demote.clone())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        send(&app, "DELETE", &ana_uri, ana.token(), None).await.0,
        StatusCode::BAD_REQUEST
    );

    // Con otro administrador, ana ya puede dejar de serlo.
    let bob_uri = format!("/v1/teams/{TEAM}/members/bob@ejemplo.com");
    let promote = json!({"role": "admin"});
    let (status, _) = send(&app, "PATCH", &bob_uri, ana.token(), Some(promote)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, "PATCH", &ana_uri, ana.token(), Some(demote)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(teams(&app, &ana).await[0].role, TeamRole::Member);

    // Un miembro puede salirse por su cuenta.
    assert_eq!(
        send(&app, "DELETE", &ana_uri, ana.token(), None).await.0,
        StatusCode::NO_CONTENT
    );
    assert!(teams(&app, &ana).await.is_empty());
    assert_eq!(teams(&app, &bob).await.len(), 1);
}

#[tokio::test]
async fn removing_a_member_and_rotating_the_key_locks_them_out() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let carol = user(&app, "carol@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    join(&app, &ana, &bob, "bob@ejemplo.com", &key).await;
    join(&app, &ana, &carol, "carol@ejemplo.com", &key).await;
    let data = VaultData {
        hosts: vec![host("db")],
        ..VaultData::default()
    };
    let (_, manifest) = push_team(&app, &ana, &key, 0, &data, &Manifest::empty()).await;

    let bob_uri = format!("/v1/teams/{TEAM}/members/bob@ejemplo.com");
    assert_eq!(
        send(&app, "DELETE", &bob_uri, ana.token(), None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(pull_team(&app, &bob).await.0, StatusCode::NOT_FOUND);

    // Ana vuelve a cifrar todo con una clave nueva para quienes quedan.
    let new_key = VaultKey::generate();
    let state = SyncState::adopt(Uuid::new_v4(), &data, 1000).unwrap();
    let outgoing = state.outgoing(&data).unwrap();
    let next = Manifest {
        version: manifest.version,
        entries: Default::default(),
    }
    .with_pushed(outgoing.iter().map(|e| (new_key.record_id(&e.key), e.hlc)));
    let rotation = |keys: Vec<MemberKey>| RotateTeamRequest {
        roster: None,
        epoch: 1,
        base_version: manifest.version,
        name: seal_team_name(&new_key, TEAM, "Equipo").unwrap(),
        keys,
        manifest: ManifestBlob {
            version: next.version,
            blob: next.seal(&new_key).unwrap(),
        },
        records: outgoing
            .iter()
            .map(|e| new_key.seal_record(e).unwrap())
            .collect(),
    };
    let wrap_for = |email: &str, public: &PublicKey| MemberKey {
        email: email.into(),
        key: wrap_team_key(&new_key, context(1), &ana.keys, public).unwrap(),
    };
    let uri = format!("/v1/teams/{TEAM}/rotate");

    // La clave nueva tiene que llegar a todos los que quedan, y a nadie más.
    let incomplete = rotation(vec![wrap_for("ana@ejemplo.com", &ana.public())]);
    let body = serde_json::to_value(incomplete).unwrap();
    assert_eq!(
        send(&app, "POST", &uri, ana.token(), Some(body)).await.0,
        StatusCode::BAD_REQUEST
    );
    let with_bob = rotation(vec![
        wrap_for("ana@ejemplo.com", &ana.public()),
        wrap_for("bob@ejemplo.com", &bob.public()),
        wrap_for("carol@ejemplo.com", &carol.public()),
    ]);
    let body = serde_json::to_value(with_bob).unwrap();
    assert_eq!(
        send(&app, "POST", &uri, ana.token(), Some(body)).await.0,
        StatusCode::BAD_REQUEST
    );

    let good = rotation(vec![
        wrap_for("ana@ejemplo.com", &ana.public()),
        wrap_for("carol@ejemplo.com", &carol.public()),
    ]);
    let body = serde_json::to_value(good).unwrap();
    let (status, body) = send(&app, "POST", &uri, ana.token(), Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Carol recibe la clave nueva y lee el contenido cifrado con ella.
    let summary = teams(&app, &carol).await.remove(0);
    assert_eq!(summary.epoch, 1);
    let carol_key = open_key(&carol, &summary);
    let (_, body) = pull_team(&app, &carol).await;
    let page: PullResponse = serde_json::from_value(body).unwrap();
    assert_eq!(page.epoch, Some(1));
    assert_eq!(hostnames(&carol_key, &page), ["db.ejemplo.com"]);
    assert!(key.open_record(&page.records[0]).is_err());

    // Lo que alguien suba aún con la clave antigua se rechaza.
    let (status, _) = push_team(&app, &carol, &key, 0, &data, &next).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = push_team(&app, &carol, &carol_key, 1, &data, &next).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn deleting_a_team_removes_it_for_everyone() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    join(&app, &ana, &bob, "bob@ejemplo.com", &key).await;
    let uri = format!("/v1/teams/{TEAM}");
    assert_eq!(
        send(&app, "DELETE", &uri, ana.token(), None).await.0,
        StatusCode::NO_CONTENT
    );
    assert!(teams(&app, &bob).await.is_empty());
    assert_eq!(pull_team(&app, &bob).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn team_ids_must_be_canonical_uuids() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let key = VaultKey::generate();
    for id in ["no-es-un-uuid", "6C2B8F0E-6F4E-4D55-9A37-1E2F3A4B5C6D"] {
        let body = serde_json::to_value(CreateTeamRequest {
            roster: None,
            id: id.into(),
            name: seal_team_name(&key, id, "x").unwrap(),
            key: wrap_team_key(&key, context(0), &ana.keys, &ana.public()).unwrap(),
        })
        .unwrap();
        let (status, _) = send(&app, "POST", "/v1/teams", ana.token(), Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{id}");
    }
    let (status, _) = send(&app, "GET", "/v1/teams/../records", ana.token(), None).await;
    assert_ne!(status, StatusCode::OK);
}

#[tokio::test]
async fn team_pushes_must_say_which_key_they_used() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    let manifest = Manifest::empty().with_pushed([]);
    let body = json!({
        "base_version": 0,
        "manifest": {"version": 1, "nonce": manifest.seal(&key).unwrap().nonce,
                     "ciphertext": manifest.seal(&key).unwrap().ciphertext},
        "records": [],
    });
    let uri = format!("/v1/teams/{TEAM}/records");
    assert_eq!(
        send(&app, "POST", &uri, ana.token(), Some(body)).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn an_invitation_gives_nothing_until_it_is_accepted() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    assert_eq!(
        invite(&app, &ana, "bob@ejemplo.com", &key, 0).await,
        StatusCode::CREATED
    );

    let invitation = teams(&app, &bob).await.remove(0);
    assert!(invitation.pending);
    assert_eq!(invitation.wrapped_by, "ana@ejemplo.com");
    assert!(invitation.key.is_none() && invitation.name.is_none());
    assert_eq!(pull_team(&app, &bob).await.0, StatusCode::NOT_FOUND);
    let members = format!("/v1/teams/{TEAM}/members");
    assert_eq!(
        send(&app, "GET", &members, bob.token(), None).await.0,
        StatusCode::NOT_FOUND
    );

    // Ana ve la invitación pendiente.
    let (_, body) = send(&app, "GET", &members, ana.token(), None).await;
    let listed: Vec<TeamMember> = serde_json::from_value(body).unwrap();
    assert!(
        listed
            .iter()
            .any(|m| m.email == "bob@ejemplo.com" && m.pending)
    );

    assert_eq!(accept(&app, &bob).await, StatusCode::NO_CONTENT);
    assert_eq!(accept(&app, &bob).await, StatusCode::NOT_FOUND);
    let joined = teams(&app, &bob).await.remove(0);
    assert!(!joined.pending);
    open_key(&bob, &joined);
    assert_eq!(pull_team(&app, &bob).await.0, StatusCode::OK);
}

#[tokio::test]
async fn declining_an_invitation_needs_no_new_key() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    invite(&app, &ana, "bob@ejemplo.com", &key, 0).await;
    let bob_uri = format!("/v1/teams/{TEAM}/members/bob@ejemplo.com");
    assert_eq!(
        send(&app, "DELETE", &bob_uri, bob.token(), None).await.0,
        StatusCode::NO_CONTENT
    );
    assert!(teams(&app, &bob).await.is_empty());
    let data = VaultData {
        hosts: vec![host("web")],
        ..VaultData::default()
    };
    let (status, _) = push_team(&app, &ana, &key, 0, &data, &Manifest::empty()).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn after_removing_a_member_nothing_is_written_until_the_key_is_renewed() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let bob = user(&app, "bob@ejemplo.com").await;
    user(&app, "carol@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    join(&app, &ana, &bob, "bob@ejemplo.com", &key).await;
    let bob_uri = format!("/v1/teams/{TEAM}/members/bob@ejemplo.com");
    assert_eq!(
        send(&app, "DELETE", &bob_uri, ana.token(), None).await.0,
        StatusCode::NO_CONTENT
    );

    let data = VaultData {
        hosts: vec![host("web")],
        ..VaultData::default()
    };
    let (status, _) = push_team(&app, &ana, &key, 0, &data, &Manifest::empty()).await;
    assert_eq!(status, StatusCode::LOCKED);
    assert_eq!(
        invite(&app, &ana, "carol@ejemplo.com", &key, 0).await,
        StatusCode::LOCKED
    );
}

/// `inviter` crea un equipo nuevo e invita a `invitee`; devuelve la respuesta a la
/// invitación.
async fn invite_to_new_team(
    app: &Router,
    inviter: &User,
    invitee: &User,
    email: &str,
) -> StatusCode {
    let team = Uuid::new_v4().to_string();
    let key = VaultKey::generate();
    let context = TeamKeyContext {
        team: &team,
        epoch: 0,
    };
    let body = serde_json::to_value(CreateTeamRequest {
        roster: None,
        id: team.clone(),
        name: seal_team_name(&key, &team, "x").unwrap(),
        key: wrap_team_key(&key, context, &inviter.keys, &inviter.public()).unwrap(),
    })
    .unwrap();
    let (status, _) = send(app, "POST", "/v1/teams", inviter.token(), Some(body)).await;
    assert_eq!(status, StatusCode::CREATED);
    let body = serde_json::to_value(AddMemberRequest {
        email: email.into(),
        role: TeamRole::Member,
        epoch: 0,
        key: wrap_team_key(&key, context, &inviter.keys, &invitee.public()).unwrap(),
    })
    .unwrap();
    let uri = format!("/v1/teams/{team}/members");
    send(app, "POST", &uri, inviter.token(), Some(body)).await.0
}

#[tokio::test]
async fn invitations_cannot_fill_up_someone_elses_account() {
    let app = app().await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let config = Config::default();
    // Aunque le lleguen invitaciones de sobra, bob puede seguir creando equipos.
    for i in 0..config.max_pending_invitations + 1 {
        let spammer = user(&app, &format!("spam{i}@ejemplo.com")).await;
        let status = invite_to_new_team(&app, &spammer, &bob, "bob@ejemplo.com").await;
        let expected = if i < config.max_pending_invitations {
            StatusCode::CREATED
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(status, expected, "invitación {i}");
    }
    create_team(&app, &bob, "Propio").await;
}

#[tokio::test]
async fn one_account_cannot_use_up_someone_elses_invitations() {
    let app = app().await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let mallory = user(&app, "mallory@ejemplo.com").await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let limit = Config::default().max_pending_from_inviter;
    for i in 0..limit {
        let status = invite_to_new_team(&app, &mallory, &bob, "bob@ejemplo.com").await;
        assert_eq!(status, StatusCode::CREATED, "invitación {i}");
    }
    assert_eq!(
        invite_to_new_team(&app, &mallory, &bob, "bob@ejemplo.com").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        invite_to_new_team(&app, &ana, &bob, "bob@ejemplo.com").await,
        StatusCode::CREATED,
        "las invitaciones de otras cuentas siguen llegando"
    );
}

#[tokio::test]
async fn only_admins_add_roster_versions_and_they_only_grow() {
    let app = app().await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    join(&app, &ana, &bob, "bob@ejemplo.com", &key).await;
    assert_eq!(teams(&app, &bob).await[0].roster_version, None);

    let roster = |epoch: u64, version: u64| {
        serde_json::to_value(RosterRequest {
            epoch,
            roster: RosterBlob {
                version,
                blob: seal_team_name(&key, TEAM, &format!("lista {version}")).unwrap(),
            },
        })
        .unwrap()
    };
    let uri = format!("/v1/teams/{TEAM}/rosters");
    let post = |user: &User, body: Value| {
        let (app, uri, token) = (app.clone(), uri.clone(), user.token().map(str::to_string));
        async move {
            send(&app, "POST", &uri, token.as_deref(), Some(body))
                .await
                .0
        }
    };
    assert_eq!(post(&bob, roster(0, 1)).await, StatusCode::FORBIDDEN);
    assert_eq!(
        post(&ana, roster(1, 1)).await,
        StatusCode::CONFLICT,
        "otra época"
    );
    assert_eq!(post(&ana, roster(0, 1)).await, StatusCode::NO_CONTENT);
    assert_eq!(
        post(&ana, roster(0, 1)).await,
        StatusCode::CONFLICT,
        "no crece"
    );
    assert_eq!(post(&ana, roster(0, 3)).await, StatusCode::NO_CONTENT);
    assert_eq!(teams(&app, &bob).await[0].roster_version, Some(3));

    // Cualquier miembro lee las versiones posteriores a la suya, en orden.
    let (status, body) = send(&app, "GET", &format!("{uri}?since=1"), bob.token(), None).await;
    assert_eq!(status, StatusCode::OK);
    let entries: Vec<RosterEntry> = serde_json::from_value(body).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].roster.version, 3);
    assert_eq!(
        open_team_name(&key, TEAM, &entries[0].roster.blob).unwrap(),
        "lista 3"
    );
}

const NOW: i64 = 1_793_404_800;

async fn admin(db: &Db, command: Command) -> Result<String, AdminError> {
    run(db, command, NOW).await
}

fn delete(email: &str, new_admin: Option<&str>, confirm: bool) -> Command {
    Command::Delete {
        email: email.into(),
        new_admin: new_admin.map(Into::into),
        confirm,
    }
}

#[tokio::test]
async fn deleting_the_only_admin_needs_a_new_one_and_the_others_keep_their_key() {
    let db = Db::open_in_memory().unwrap();
    let app = app_on(db.clone()).await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let carol = user(&app, "carol@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    join(&app, &ana, &bob, "bob@ejemplo.com", &key).await;
    join(&app, &ana, &carol, "carol@ejemplo.com", &key).await;

    // Una cuenta con el correo que tendría la lápida de Ana, registrada antes de que el
    // servidor rechazara los correos `.invalid`, no impide borrarla.
    db.insert_account(
        NewAccount {
            email: "borrada-1@cuenta.invalid".into(),
            kdf: KdfParams::RECOMMENDED,
            salt: B64.encode(SALT),
            auth: StoredHash {
                salt: vec![0; 16],
                hash: vec![0; 32],
                kdf: KdfParams::FAST_FOR_TESTS,
            },
            vault_key: VaultKey::generate().wrap(&account("x")).unwrap(),
            created_at: NOW,
        },
        false,
    )
    .await
    .unwrap();

    let listed = admin(&db, Command::Accounts).await.unwrap();
    assert!(
        listed.contains("ana@ejemplo.com") && listed.contains("4 cuentas"),
        "{listed}"
    );
    let alone = admin(&db, delete("ana@ejemplo.com", None, true)).await;
    assert!(
        matches!(alone, Err(AdminError::NeedsNewAdmin { .. })),
        "{alone:?}"
    );
    let outsider = admin(
        &db,
        delete("ana@ejemplo.com", Some("nadie@ejemplo.com"), true),
    )
    .await;
    assert!(
        matches!(outsider, Err(AdminError::NoAccount(_))),
        "{outsider:?}"
    );

    // Sin --confirmar solo se cuenta lo que pasaría.
    let preview = admin(
        &db,
        delete("ana@ejemplo.com", Some("carol@ejemplo.com"), false),
    )
    .await
    .unwrap();
    assert!(preview.contains("--confirmar"), "{preview}");
    assert_eq!(teams(&app, &ana).await.len(), 1);

    let done = admin(
        &db,
        delete("ana@ejemplo.com", Some("carol@ejemplo.com"), true),
    )
    .await
    .unwrap();
    assert!(done.contains("borrada"), "{done}");
    assert_eq!(
        send(&app, "GET", "/v1/teams", ana.token(), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let listed = admin(&db, Command::Accounts).await.unwrap();
    assert!(!listed.contains("ana@"), "{listed}");
    assert!(
        !listed.contains("borrada-1-"),
        "la lápida no se lista: {listed}"
    );

    // La lápida no sirve para entrar, aunque alguien adivine su correo.
    let tombstone = json!({
        "email": "borrada-1@cuenta.invalid",
        "auth": account("ana@ejemplo.com").auth_token().as_str(),
    });
    let (status, _) = send(&app, "POST", "/v1/sessions", None, Some(tombstone)).await;
    assert!(!status.is_success(), "{status}");

    // Bob sigue abriendo la clave que envolvió Ana: su clave pública se conserva.
    let summary = teams(&app, &bob).await.remove(0);
    assert_eq!(
        open_key(&bob, &summary).record_id(&probe()),
        key.record_id(&probe())
    );
    // Pero no se sube nada hasta renovar la clave, que ahora puede hacer Carol.
    let data = VaultData {
        hosts: vec![host("web")],
        ..VaultData::default()
    };
    let (status, _) = push_team(&app, &bob, &key, 0, &data, &Manifest::empty()).await;
    assert_eq!(status, StatusCode::LOCKED);

    let new_key = VaultKey::generate();
    let wrap_for = |email: &str, public: &PublicKey| MemberKey {
        email: email.into(),
        key: wrap_team_key(&new_key, context(1), &carol.keys, public).unwrap(),
    };
    let next = Manifest::empty().with_pushed(std::iter::empty());
    let rotation = RotateTeamRequest {
        roster: None,
        epoch: 1,
        base_version: 0,
        name: seal_team_name(&new_key, TEAM, "Equipo").unwrap(),
        keys: vec![
            wrap_for("bob@ejemplo.com", &bob.public()),
            wrap_for("carol@ejemplo.com", &carol.public()),
        ],
        manifest: ManifestBlob {
            version: next.version,
            blob: next.seal(&new_key).unwrap(),
        },
        records: Vec::new(),
    };
    let uri = format!("/v1/teams/{TEAM}/rotate");
    let body = serde_json::to_value(rotation).unwrap();
    let (status, body) = send(&app, "POST", &uri, carol.token(), Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let summary = teams(&app, &bob).await.remove(0);
    assert_eq!(
        open_key(&bob, &summary).record_id(&probe()),
        new_key.record_id(&probe())
    );
    // Ya nadie depende de la lápida: se borró y el correo se puede volver a usar.
    user(&app, "ana@ejemplo.com").await;
}

fn probe() -> tunel_core::sync::RecordKey {
    tunel_core::sync::RecordKey::new(tunel_core::sync::RecordKind::Host, "x")
}

#[tokio::test]
async fn a_team_with_nobody_else_is_deleted_and_sessions_can_be_closed() {
    let db = Db::open_in_memory().unwrap();
    let app = app_on(db.clone()).await;
    let ana = user(&app, "ana@ejemplo.com").await;
    let bob = user(&app, "bob@ejemplo.com").await;
    let key = create_team(&app, &ana, "Equipo").await;
    // Una invitación pendiente no cuenta como alguien más.
    assert_eq!(
        invite(&app, &ana, "bob@ejemplo.com", &key, 0).await,
        StatusCode::CREATED
    );

    let closed = admin(&db, Command::CloseSessions("bob@ejemplo.com".into()))
        .await
        .unwrap();
    assert!(closed.contains("Cerradas 1 sesiones"), "{closed}");
    assert_eq!(
        send(&app, "GET", "/v1/teams", bob.token(), None).await.0,
        StatusCode::UNAUTHORIZED
    );

    let done = admin(&db, delete("ana@ejemplo.com", None, true))
        .await
        .unwrap();
    assert!(done.contains("Teams borrados"), "{done}");
    let bob = login(&app, "bob@ejemplo.com").await;
    let (status, body) = send(&app, "GET", "/v1/teams", Some(&bob.token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!([]));
}
