package dev.tunel.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.tunel_mobile.GroupSummary
import uniffi.tunel_mobile.HostSummary

class HostTreeTest {
    private fun group(id: String, parent: String? = null) =
        GroupSummary(id, id.replaceFirstChar { it.uppercase() }, parent, null, null)

    private fun host(
        label: String,
        group: String? = null,
        tags: List<String> = emptyList(),
        port: Int = 22,
    ) = HostSummary(label, label, "$label.example.com", port.toUShort(), "SSH", group, null, tags)

    @Test
    fun subgroupsHangFromTheirParent() {
        val tree = HostTree(emptyList(), listOf(group("clientes"), group("acme", "clientes")))

        assertEquals(listOf("clientes"), tree.roots.map { it.id })
        assertEquals(listOf("acme"), tree.roots[0].children.map { it.id })
    }

    @Test
    fun rowsListEachGroupAfterItsParentWithItsDepth() {
        val tree = HostTree(
            emptyList(),
            listOf(group("acme", "clientes"), group("clientes"), group("casa")),
        )

        // Los grupos llegan del núcleo ya ordenados por nombre; el árbol respeta ese orden.
        assertEquals(
            listOf("clientes" to 0, "acme" to 1, "casa" to 0),
            tree.rows().map { it.group.id to it.depth },
        )
    }

    @Test
    fun aGroupWhoseParentIsGoneGoesToTheRoot() {
        val tree = HostTree(emptyList(), listOf(group("huérfano", "borrado")))

        assertEquals(listOf("huérfano"), tree.roots.map { it.id })
    }

    @Test
    fun aCycleDoesNotHang() {
        val tree = HostTree(emptyList(), listOf(group("a", "b"), group("b", "a")))

        assertTrue(tree.roots.isEmpty())
        assertTrue(tree.hosts(inGroup = "a").isEmpty())
    }

    @Test
    fun aGroupIncludesTheHostsOfItsSubgroups() {
        val tree = HostTree(
            listOf(host("web", "acme"), host("db", "clientes"), host("suelto")),
            listOf(group("clientes"), group("acme", "clientes")),
        )

        assertEquals(setOf("web", "db"), tree.hosts(inGroup = "clientes").map { it.label }.toSet())
        assertEquals(listOf("web"), tree.hosts(inGroup = "acme").map { it.label })
        assertEquals(3, tree.hosts(inGroup = null).size)
    }

    @Test
    fun searchLooksAtNameAddressAndTagsIgnoringCase() {
        val tree = HostTree(
            listOf(host("web", tags = listOf("Prod")), host("db"), host("cache")),
            emptyList(),
        )

        assertEquals(listOf("web"), tree.hosts(null, "prod").map { it.label })
        assertEquals(listOf("db"), tree.hosts(null, " DB.EXAMPLE ").map { it.label })
        assertEquals(3, tree.hosts(null, "   ").size)
    }

    @Test
    fun theEndpointHidesTheUsualSshPort() {
        assertEquals("web.example.com", host("web").endpoint)
        assertEquals("web.example.com:2222", host("web", port = 2222).endpoint)
    }
}
