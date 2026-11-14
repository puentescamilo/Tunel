package dev.tunel.android.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class JumpListTest {
    @Test
    fun movingUpSwapsWithThePreviousOne() {
        assertEquals(listOf("b", "a", "c"), listOf("a", "b", "c").moveUp("b"))
    }

    @Test
    fun theFirstOneOrAMissingOneStaysPut() {
        assertEquals(listOf("a", "b"), listOf("a", "b").moveUp("a"))
        assertEquals(listOf("a", "b"), listOf("a", "b").moveUp("z"))
    }
}
