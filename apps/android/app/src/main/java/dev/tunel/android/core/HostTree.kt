package dev.tunel.android.core

import uniffi.tunel_mobile.GroupSummary
import uniffi.tunel_mobile.HostSummary

/** Un grupo con sus subgrupos, ya colocado en el árbol. */
data class GroupNode(val group: GroupSummary, val children: List<GroupNode>) {
    val id: String get() = group.id
}

/** Un grupo con su profundidad, para pintar el árbol como una lista sangrada. */
data class GroupRow(val group: GroupSummary, val depth: Int)

/** Los grupos de la bóveda en forma de árbol y los hosts de cada rama. */
class HostTree(val hosts: List<HostSummary>, groups: List<GroupSummary>) {
    private val groupsById: Map<String, GroupSummary> = groups.associateBy { it.id }

    // Un padre que ya no existe deja al grupo en la raíz, como en el escritorio.
    private val childrenByParent: Map<String, List<GroupSummary>> = groups.groupBy { group ->
        group.parentId?.takeIf { it in groupsById } ?: ROOT
    }

    val roots: List<GroupNode> = nodes(under = ROOT, visited = emptySet())

    fun group(id: String): GroupSummary? = groupsById[id]

    /** El árbol en orden, cada grupo tras su padre. */
    fun rows(): List<GroupRow> {
        val rows = mutableListOf<GroupRow>()
        fun walk(nodes: List<GroupNode>, depth: Int) {
            for (node in nodes) {
                rows += GroupRow(node.group, depth)
                walk(node.children, depth + 1)
            }
        }
        walk(roots, 0)
        return rows
    }

    /** Los hosts del grupo y de todos sus subgrupos; con `null`, todos los hosts. */
    fun hosts(inGroup: String?, matching: String = ""): List<HostSummary> {
        val inBranch = if (inGroup == null) {
            hosts
        } else {
            val branch = descendants(inGroup) + inGroup
            hosts.filter { it.groupId in branch }
        }
        val needle = matching.trim()
        if (needle.isEmpty()) return inBranch
        return inBranch.filter { it.matches(needle) }
    }

    private fun descendants(groupId: String): Set<String> {
        val found = mutableSetOf<String>()
        val pending = ArrayDeque(listOf(groupId))
        while (pending.isNotEmpty()) {
            for (child in childrenByParent[pending.removeLast()].orEmpty()) {
                if (found.add(child.id)) pending.addLast(child.id)
            }
        }
        return found
    }

    /** `visited` corta los ciclos que pudiera traer una bóveda dañada. */
    private fun nodes(under: String, visited: Set<String>): List<GroupNode> =
        childrenByParent[under].orEmpty()
            .filter { it.id !in visited }
            .map { GroupNode(it, nodes(it.id, visited + it.id)) }

    companion object {
        val EMPTY = HostTree(emptyList(), emptyList())
        private const val ROOT = ""
    }
}

/** La misma búsqueda que el escritorio: nombre, dirección o etiquetas, sin mayúsculas. */
fun HostSummary.matches(query: String): Boolean =
    (listOf(label, address) + tags).any { it.contains(query, ignoreCase = true) }

/** «dirección:puerto», o solo la dirección si el puerto es el habitual de SSH. */
val HostSummary.endpoint: String
    get() = if (port.toInt() == 22 || port.toInt() == 0) address else "$address:$port"
