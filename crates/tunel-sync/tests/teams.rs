//! Teams de punta a punta contra un `tunel-server` real: varias cuentas comparten hosts,
//! los cambios llegan a todos, quien sale deja de recibirlos y una clave suplantada se
//! detecta.

use tunel_core::crypto::KdfParams;
use tunel_core::model::Host;
use tunel_core::sync::protocol::TeamRole;
use tunel_core::sync::{AccountKeypair, Contact, SyncLocal};
use tunel_core::vault::VaultData;
use tunel_server::{AppState, Config, Db, router};
use tunel_sync::teams::{self, KeyStatus};
use tunel_sync::{ServerUrl, SyncError, check_server_url, create_account, sync_once};
use zeroize::Zeroizing;

async fn start_server() -> ServerUrl {
    let config = Config {
        auth_kdf: KdfParams::FAST_FOR_TESTS,
        open_registration: true,
        unauthenticated_burst: 1000,
        ..Config::default()
    };
    let state = AppState::new(Db::open_in_memory().unwrap(), config)
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    check_server_url(&format!("http://{address}")).unwrap()
}

/// Una cuenta con un único equipo: su bóveda y su configuración.
struct Person {
    data: VaultData,
    local: SyncLocal,
}

impl Person {
    async fn new(server: &ServerUrl, email: &str, data: VaultData) -> Self {
        let password = Zeroizing::new(format!("contraseña de {email}"));
        let local = create_account(server, email, password, &data)
            .await
            .unwrap();
        Self { data, local }
    }

    async fn sync(&mut self) -> tunel_sync::SyncOutcome {
        let outcome = sync_once(&self.local, &self.data).await.unwrap();
        self.data = outcome.data.clone();
        self.local = outcome.local.clone();
        outcome
    }

    fn edit(&mut self, new: VaultData) {
        self.local = self.local.record_local(&self.data, &new, now()).unwrap();
        self.data = new;
    }

    /// Mueve el host `label` al Team `team`, o a la bóveda personal con `None`.
    fn move_host(&mut self, label: &str, team: Option<&str>) {
        let mut new = self.data.clone();
        let host = new.hosts.iter_mut().find(|h| h.label == label).unwrap();
        host.team = team.map(str::to_string);
        self.edit(new);
    }

    fn host(&self, label: &str) -> Option<&Host> {
        self.data.hosts.iter().find(|h| h.label == label)
    }

    async fn create_team(&mut self, name: &str) -> String {
        let (local, id) = teams::create_team(&self.local, name).await.unwrap();
        self.local = local;
        id
    }

    async fn invite(&mut self, team: &str, email: &str) {
        let (local, _) = teams::invite(&self.local, team, email, TeamRole::Member)
            .await
            .unwrap();
        self.local = local;
    }

    async fn accept(&mut self, team: &str) {
        self.sync().await;
        assert!(self.local.invitations.iter().any(|i| i.team == team));
        self.local = teams::accept_invitation(&self.local, team).await.unwrap();
        self.sync().await;
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn hosts(labels: &[&str]) -> VaultData {
    labels.iter().fold(VaultData::default(), |d, l| {
        d.with_host(Host::new(*l, "10.0.0.1"))
    })
}

/// Ana crea un Team y comparte el host «web» con bob.
async fn shared_team(server: &ServerUrl) -> (Person, Person, String) {
    let mut ana = Person::new(server, "ana@ejemplo.com", hosts(&["web", "privado-ana"])).await;
    let mut bob = Person::new(server, "bob@ejemplo.com", hosts(&["privado-bob"])).await;
    ana.sync().await;
    bob.sync().await;
    let team = ana.create_team("Infraestructura").await;
    ana.invite(&team, "bob@ejemplo.com").await;
    bob.accept(&team).await;
    ana.move_host("web", Some(&team));
    ana.sync().await;
    bob.sync().await;
    (ana, bob, team)
}

#[tokio::test]
async fn a_shared_host_reaches_the_member_and_private_ones_do_not() {
    let server = start_server().await;
    let (ana, bob, team) = shared_team(&server).await;
    assert_eq!(bob.local.team(&team).unwrap().name, "Infraestructura");
    assert_eq!(
        bob.host("web").unwrap().team.as_deref(),
        Some(team.as_str())
    );
    assert!(bob.host("privado-ana").is_none());
    assert!(ana.host("privado-bob").is_none());
    assert_eq!(ana.local.pending(), 0);
}

#[tokio::test]
async fn edits_from_any_member_reach_everyone() {
    let server = start_server().await;
    let (mut ana, mut bob, _) = shared_team(&server).await;
    let mut edited = bob.data.clone();
    edited
        .hosts
        .iter_mut()
        .find(|h| h.label == "web")
        .unwrap()
        .address = "10.9.9.9".into();
    bob.edit(edited);
    bob.sync().await;
    ana.sync().await;
    assert_eq!(ana.host("web").unwrap().address, "10.9.9.9");
}

#[tokio::test]
async fn moving_a_host_back_to_the_personal_vault_unshares_it() {
    let server = start_server().await;
    let (mut ana, mut bob, _) = shared_team(&server).await;
    ana.move_host("web", None);
    ana.sync().await;
    bob.sync().await;
    assert!(bob.host("web").is_none());
    assert_eq!(ana.host("web").unwrap().team, None);
    // Y sigue en la bóveda personal de ana tras otra ronda.
    ana.sync().await;
    assert!(ana.host("web").is_some());
}

#[tokio::test]
async fn a_removed_member_loses_the_team_and_the_rest_keep_working() {
    let server = start_server().await;
    let (mut ana, mut bob, team) = shared_team(&server).await;
    let mut carol = Person::new(&server, "carol@ejemplo.com", VaultData::default()).await;
    carol.sync().await;
    ana.invite(&team, "carol@ejemplo.com").await;
    carol.accept(&team).await;
    assert!(carol.host("web").is_some());

    let (local, data) = teams::remove_member(&ana.local, &ana.data, &team, "bob@ejemplo.com")
        .await
        .unwrap();
    ana.local = local;
    ana.data = data;
    assert_eq!(ana.local.team(&team).unwrap().epoch, 1);

    bob.sync().await;
    assert!(bob.local.team(&team).is_none());
    assert!(bob.host("web").is_none());
    assert!(bob.host("privado-bob").is_some());

    // Carol recibe la clave nueva y sigue pudiendo editar.
    carol.sync().await;
    assert_eq!(carol.local.team(&team).unwrap().epoch, 1);
    carol.edit(carol.data.with_host({
        let mut h = Host::new("nuevo", "10.0.0.2");
        h.team = Some(team.clone());
        h
    }));
    let outcome = carol.sync().await;
    assert!(
        outcome.team_problems.is_empty(),
        "{:?}",
        outcome.team_problems
    );
    ana.sync().await;
    assert!(ana.host("nuevo").is_some());
}

#[tokio::test]
async fn when_a_member_leaves_an_admin_renews_the_key_on_its_next_sync() {
    let server = start_server().await;
    let (mut ana, mut bob, team) = shared_team(&server).await;
    let (local, data) = teams::leave_team(&bob.local, &bob.data, &team)
        .await
        .unwrap();
    bob.local = local;
    bob.data = data;
    assert!(bob.host("web").is_none());

    let outcome = ana.sync().await;
    assert!(
        outcome.team_problems.is_empty(),
        "{:?}",
        outcome.team_problems
    );
    assert_eq!(ana.local.team(&team).unwrap().epoch, 1);
}

#[tokio::test]
async fn an_invitation_with_a_swapped_key_is_refused() {
    let server = start_server().await;
    let mut ana = Person::new(&server, "ana@ejemplo.com", VaultData::default()).await;
    let mut bob = Person::new(&server, "bob@ejemplo.com", VaultData::default()).await;
    ana.sync().await;
    bob.sync().await;
    let team = ana.create_team("Equipo").await;
    // Ana ya conocía otra clave para bob: la del servidor no coincide.
    let impostor = AccountKeypair::generate().public();
    ana.local.contacts.insert(
        "bob@ejemplo.com".into(),
        Contact {
            key: impostor,
            verified: true,
        },
    );
    let result = teams::invite(&ana.local, &team, "bob@ejemplo.com", TeamRole::Member).await;
    assert!(matches!(result, Err(SyncError::KeyChanged(_))));
}

#[tokio::test]
async fn a_team_key_wrapped_by_an_unknown_key_is_not_accepted() {
    let server = start_server().await;
    let mut ana = Person::new(&server, "ana@ejemplo.com", VaultData::default()).await;
    let mut bob = Person::new(&server, "bob@ejemplo.com", VaultData::default()).await;
    ana.sync().await;
    bob.sync().await;
    let team = ana.create_team("Equipo").await;
    ana.invite(&team, "bob@ejemplo.com").await;
    // Bob tenía fijada otra clave para ana: la clave del Team podría venir de un impostor.
    bob.local.contacts.insert(
        "ana@ejemplo.com".into(),
        Contact {
            key: AccountKeypair::generate().public(),
            verified: false,
        },
    );
    bob.sync().await;
    bob.local = teams::accept_invitation(&bob.local, &team).await.unwrap();
    let outcome = bob.sync().await;
    assert!(bob.local.team(&team).is_none());
    assert_eq!(outcome.team_problems.len(), 1);
}

#[tokio::test]
async fn an_older_team_key_from_the_server_is_refused() {
    let server = start_server().await;
    let (_, mut bob, team) = shared_team(&server).await;
    // Bob ya había visto una época posterior a la que da el servidor.
    bob.local.teams[0].epoch = 5;
    let outcome = bob.sync().await;
    assert_eq!(outcome.team_problems.len(), 1);
    assert!(outcome.team_problems[0].message.contains("anterior"));
    assert_eq!(bob.local.team(&team).unwrap().epoch, 5);
}

#[tokio::test]
async fn members_show_the_state_of_their_keys() {
    let server = start_server().await;
    let (ana, _, team) = shared_team(&server).await;
    let (_, members) = teams::members(&ana.local, &team).await.unwrap();
    let status = |email: &str| members.iter().find(|m| m.email == email).unwrap().key;
    assert_eq!(status("ana@ejemplo.com"), KeyStatus::Own);
    assert_eq!(status("bob@ejemplo.com"), KeyStatus::Pinned);
    let verified = teams::mark_verified(&ana.local, "bob@ejemplo.com");
    let (_, members) = teams::members(&verified, &team).await.unwrap();
    assert!(members.iter().any(|m| m.key == KeyStatus::Verified));
}

#[tokio::test]
async fn only_admins_manage_the_team() {
    let server = start_server().await;
    let (_, bob, team) = shared_team(&server).await;
    let result = teams::invite(&bob.local, &team, "ana@ejemplo.com", TeamRole::Member).await;
    assert!(matches!(result, Err(SyncError::Forbidden(_))));
    let result = teams::remove_member(&bob.local, &bob.data, &team, "ana@ejemplo.com").await;
    assert!(matches!(result, Err(SyncError::Forbidden(_))));
}

#[tokio::test]
async fn deleting_the_team_removes_its_hosts_everywhere() {
    let server = start_server().await;
    let (mut ana, mut bob, team) = shared_team(&server).await;
    let (local, data) = teams::delete_team(&ana.local, &ana.data, &team)
        .await
        .unwrap();
    ana.local = local;
    ana.data = data;
    assert!(ana.host("web").is_none());
    bob.sync().await;
    assert!(bob.host("web").is_none());
    assert!(bob.local.teams.is_empty());
}
