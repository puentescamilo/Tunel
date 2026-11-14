package dev.tunel.android.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PermanentDrawerSheet
import androidx.compose.material3.PermanentNavigationDrawer
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.tunel.android.core.HostTree
import dev.tunel.android.core.SyncStatus
import dev.tunel.android.core.VaultStore
import dev.tunel.android.core.endpoint
import kotlinx.coroutines.launch
import uniffi.tunel_mobile.HostSummary

/** A partir de este ancho, los grupos quedan siempre a la vista (tabletas y plegables). */
private const val WIDE_SCREEN_DP = 840

/** Grupos en el cajón lateral y los hosts del grupo elegido, con búsqueda. */
@Composable
fun HostsScreen(state: VaultStore.State, onLock: () -> Unit, account: AccountCallbacks) {
    val tree = state.tree
    // `null` es «Todos los hosts»; si no, el id de un grupo.
    var groupId by rememberSaveable { mutableStateOf<String?>(null) }
    var hostId by rememberSaveable { mutableStateOf<String?>(null) }
    var showingAccount by rememberSaveable { mutableStateOf(false) }
    val selectedHost = hostId?.let { id -> tree.hosts.firstOrNull { it.id == id } }

    // Al abrir la bóveda, lo nuevo de la cuenta (si está unida; si no, no hace nada).
    LaunchedEffect(Unit) { account.onSync() }

    if (showingAccount) {
        BackHandler { showingAccount = false }
        AccountScreen(
            account = state.account,
            sync = state.sync,
            signIn = state.signIn,
            callbacks = account,
            onBack = { showingAccount = false },
        )
        return
    }

    if (selectedHost != null) {
        BackHandler { hostId = null }
        HostDetailScreen(selectedHost, onBack = { hostId = null })
        return
    }

    val wide = LocalConfiguration.current.screenWidthDp >= WIDE_SCREEN_DP
    val drawer = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val groups = @Composable {
        GroupList(tree, groupId) {
            groupId = it
            scope.launch { drawer.close() }
        }
    }
    val content = @Composable {
        HostListScaffold(
            state = state,
            groupId = groupId,
            onMenu = if (wide) null else ({ scope.launch { drawer.open() } }),
            onLock = onLock,
            onAccount = { showingAccount = true },
            onSync = account.onSync,
            onOpen = { hostId = it.id },
        )
    }

    if (wide) {
        PermanentNavigationDrawer(drawerContent = {
            PermanentDrawerSheet(Modifier.width(300.dp)) { groups() }
        }) { content() }
    } else {
        ModalNavigationDrawer(drawerState = drawer, drawerContent = {
            ModalDrawerSheet { groups() }
        }) { content() }
    }
}

@Composable
private fun GroupList(tree: HostTree, selected: String?, onSelect: (String?) -> Unit) {
    Column(
        Modifier
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 12.dp, vertical = 16.dp),
    ) {
        Text(
            "Túnel",
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(start = 16.dp, bottom = 12.dp),
        )
        NavigationDrawerItem(
            label = { Text("Todos los hosts") },
            selected = selected == null,
            onClick = { onSelect(null) },
        )
        val rows = tree.rows()
        if (rows.isNotEmpty()) {
            HorizontalDivider(Modifier.padding(vertical = 8.dp))
            Text(
                "Grupos",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 16.dp, bottom = 4.dp),
            )
            for (row in rows) {
                NavigationDrawerItem(
                    label = { Text(row.group.name) },
                    selected = selected == row.group.id,
                    onClick = { onSelect(row.group.id) },
                    modifier = Modifier.padding(start = (row.depth * 16).dp),
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HostListScaffold(
    state: VaultStore.State,
    groupId: String?,
    onMenu: (() -> Unit)?,
    onLock: () -> Unit,
    onAccount: () -> Unit,
    onSync: () -> Unit,
    onOpen: (HostSummary) -> Unit,
) {
    val tree = state.tree
    val hasAccount = state.account != null
    // `remember`: lo buscado (nombres, direcciones) no va al estado que Android guarda.
    var query by remember { mutableStateOf("") }
    val title = groupId?.let { tree.group(it)?.name } ?: "Todos los hosts"
    val hosts = tree.hosts(groupId, query)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    if (onMenu != null) {
                        IconButton(onClick = onMenu) {
                            Icon(Icons.Filled.Menu, contentDescription = "Grupos")
                        }
                    }
                },
                actions = {
                    IconButton(onClick = onAccount) {
                        Icon(Icons.Filled.AccountCircle, contentDescription = "Cuenta")
                    }
                    IconButton(onClick = onLock) {
                        Icon(Icons.Filled.Lock, contentDescription = "Bloquear")
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("Nombre, dirección o etiqueta") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { query = "" }) {
                            Icon(Icons.Filled.Clear, contentDescription = "Borrar búsqueda")
                        }
                    }
                },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
            )
            if (hasAccount) {
                SyncStatusText(state.sync, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
            }
            val list = @Composable {
                if (hosts.isEmpty()) {
                    EmptyHosts(searching = query.isNotBlank(), hasAccount, onAccount)
                } else {
                    LazyColumn(contentPadding = PaddingValues(bottom = 16.dp)) {
                        items(hosts, key = { it.id }) { host -> HostRow(host) { onOpen(host) } }
                    }
                }
            }
            // Deslizar hacia abajo sincroniza, si el dispositivo está unido a una cuenta.
            if (hasAccount) {
                PullToRefreshBox(
                    isRefreshing = state.sync == SyncStatus.Syncing,
                    onRefresh = onSync,
                    modifier = Modifier.fillMaxSize(),
                ) { list() }
            } else {
                list()
            }
        }
    }
}

@Composable
private fun EmptyHosts(searching: Boolean, hasAccount: Boolean, onAccount: () -> Unit) {
    // Desplazable: si no, deslizar hacia abajo no llega a sincronizar con la lista vacía.
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(32.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            if (searching) "Ningún host coincide" else "No hay hosts",
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            if (searching) "Prueba con otro nombre, dirección o etiqueta." else "Los hosts de tu cuenta de Túnel aparecerán aquí.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (!searching && !hasAccount) {
            Button(onClick = onAccount) { Text("Iniciar sesión") }
        }
    }
}

@Composable
private fun HostRow(host: HostSummary, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(host.label) },
        supportingContent = {
            Text(
                host.endpoint,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
            )
        },
        overlineContent = host.team?.let { team -> { Text("Team · $team") } },
        trailingContent = if (host.protocol != "SSH") {
            { SuggestionChip(onClick = onClick, label = { Text(host.protocol) }) }
        } else {
            null
        },
        modifier = Modifier.clickable(onClick = onClick),
    )
}
