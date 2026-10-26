@file:OptIn(androidx.compose.ui.text.ExperimentalTextApi::class)

package com.thymus.tgwsproxy.ui

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.thymus.tgwsproxy.R

enum class ThemeMode { LIGHT, DARK }

/**
 * The active theme. It is snapshot state, so every colour read from [Palette] during
 * composition is invalidated when the user switches between light and dark.
 */
object ThemeState {
    var mode by mutableStateOf(ThemeMode.LIGHT)
        private set

    val isDark: Boolean get() = mode == ThemeMode.DARK

    fun set(mode: ThemeMode) {
        this.mode = mode
    }
}

/**
 * Two botanical palettes from the design references. Light: lavender canvas, milk-white
 * cards, pine-green text. Dark: the night version of the same illustration, deep plum
 * surfaces, a brighter pine and a purple traffic panel.
 *
 * The getters read [ThemeState], so switching the theme recomposes every screen that
 * uses a colour, without threading a palette through every composable.
 */
object Palette {
    private val dark: Boolean get() = ThemeState.isDark

    /** Brand fill: power button, Telegram pill, gear. */
    val Pine: Color get() = if (dark) Color(0xFF1E5551) else Color(0xFF0E4B4A)

    /** Primary text and icons on cards and on the page. */
    val Ink: Color get() = if (dark) Color(0xFFEDE6F5) else Color(0xFF0E4B4A)

    /** Text and icons on a pine fill. */
    val OnPine: Color get() = if (dark) Color(0xFFF4EFC4) else Color(0xFFEDE3F7)

    /** Traffic panel and the text inside it. */
    val LavenderPaper: Color get() = if (dark) Color(0xFF64457E) else Color(0xFFEDE3F7)
    val OnCard: Color get() = if (dark) Color(0xFFEFE4F7) else Color(0xFF0E4B4A)

    /** Page canvas: lavender in light, the night background base in dark. */
    val Lavender: Color get() = if (dark) Color(0xFF261F30) else Color(0xFFB99AEF)
    val LavenderLight: Color get() = if (dark) Color(0xFF3A3149) else Color(0xFFEDE5FB)
    val Milk: Color get() = if (dark) Color(0xFF322A3F) else Color(0xFFFDFCF8)
    val Champagne: Color get() = if (dark) Color(0xFFE9E2B4) else Color(0xFFD8D6A6)
    val ChampagneLight: Color get() = if (dark) Color(0xFFF4EFC4) else Color(0xFFE9E6BE)
    val ChampagneDeep: Color get() = if (dark) Color(0xFFD8D2A0) else Color(0xFFC6C187)

    /** Secondary text and subtle borders. */
    val PineMuted: Color get() = if (dark) Color(0xFFB6A8C8) else Color(0xFF4F7A77)
    val PineFaint: Color get() = if (dark) Color(0xFF8C7FA0) else Color(0xFF9DB5B2)
    val LavenderDeep: Color get() = if (dark) Color(0xFFB79BE8) else Color(0xFF9C7BD9)
    val OutlineSoft: Color get() = if (dark) Color(0xFF3C3450) else Color(0xFFDCE5E2)
}

/** Geologica: geometric, slightly quirky sans that matches the reference mockup. */
private val ThymusFont = FontFamily(
    Font(
        R.font.geologica,
        weight = FontWeight.Normal,
        variationSettings = FontVariation.Settings(FontVariation.weight(400)),
    ),
    Font(
        R.font.geologica,
        weight = FontWeight.Medium,
        variationSettings = FontVariation.Settings(FontVariation.weight(500)),
    ),
    Font(
        R.font.geologica,
        weight = FontWeight.SemiBold,
        variationSettings = FontVariation.Settings(FontVariation.weight(600)),
    ),
    Font(
        R.font.geologica,
        weight = FontWeight.Bold,
        variationSettings = FontVariation.Settings(FontVariation.weight(700)),
    ),
    Font(
        R.font.geologica,
        weight = FontWeight.ExtraBold,
        variationSettings = FontVariation.Settings(FontVariation.weight(800)),
    ),
)

private val ThymusTypography: Typography = Typography().let { base ->
    Typography(
        displayLarge = base.displayLarge.copy(fontFamily = ThymusFont),
        displayMedium = base.displayMedium.copy(fontFamily = ThymusFont),
        displaySmall = base.displaySmall.copy(fontFamily = ThymusFont),
        headlineLarge = base.headlineLarge.copy(fontFamily = ThymusFont),
        headlineMedium = base.headlineMedium.copy(fontFamily = ThymusFont),
        headlineSmall = base.headlineSmall.copy(fontFamily = ThymusFont),
        titleLarge = base.titleLarge.copy(fontFamily = ThymusFont),
        titleMedium = base.titleMedium.copy(fontFamily = ThymusFont),
        titleSmall = base.titleSmall.copy(fontFamily = ThymusFont),
        bodyLarge = base.bodyLarge.copy(fontFamily = ThymusFont),
        bodyMedium = base.bodyMedium.copy(fontFamily = ThymusFont),
        bodySmall = base.bodySmall.copy(fontFamily = ThymusFont),
        labelLarge = base.labelLarge.copy(fontFamily = ThymusFont),
        labelMedium = base.labelMedium.copy(fontFamily = ThymusFont),
        labelSmall = base.labelSmall.copy(fontFamily = ThymusFont),
    )
}

@Composable
private fun thymusLightColors() = lightColorScheme(
        primary = Palette.Pine,
        onPrimary = Palette.OnPine,
        primaryContainer = Palette.LavenderLight,
        onPrimaryContainer = Palette.Ink,
        secondary = Palette.Lavender,
        onSecondary = Palette.Ink,
        secondaryContainer = Palette.LavenderLight,
        onSecondaryContainer = Palette.Ink,
        tertiary = Palette.Champagne,
        onTertiary = Palette.Ink,
        tertiaryContainer = Palette.Champagne,
        onTertiaryContainer = Palette.Ink,
        background = Palette.Lavender,
        onBackground = Palette.Ink,
        surface = Palette.Milk,
        onSurface = Palette.Ink,
        surfaceVariant = Palette.LavenderLight,
        onSurfaceVariant = Palette.PineMuted,
        outline = Palette.PineFaint,
        outlineVariant = Palette.OutlineSoft,
        error = Color(0xFF9B3B3B),
        onError = Palette.Milk,
        errorContainer = Color(0xFFF0D7D1),
        onErrorContainer = Color(0xFF5A1F1F),
        inverseSurface = Palette.Pine,
        inverseOnSurface = Palette.Milk,
    )

@Composable
private fun thymusDarkColors() = darkColorScheme(
        primary = Palette.Pine,
        onPrimary = Palette.OnPine,
        primaryContainer = Palette.LavenderLight,
        onPrimaryContainer = Palette.Ink,
        secondary = Palette.LavenderDeep,
        onSecondary = Palette.Ink,
        secondaryContainer = Palette.LavenderLight,
        onSecondaryContainer = Palette.Ink,
        tertiary = Palette.Champagne,
        onTertiary = Palette.Pine,
        tertiaryContainer = Palette.Champagne,
        onTertiaryContainer = Palette.Pine,
        background = Palette.Lavender,
        onBackground = Palette.Ink,
        surface = Palette.Milk,
        onSurface = Palette.Ink,
        surfaceVariant = Palette.LavenderLight,
        onSurfaceVariant = Palette.PineMuted,
        outline = Palette.PineFaint,
        outlineVariant = Palette.OutlineSoft,
        error = Color(0xFFE9A7A7),
        onError = Color(0xFF3A1D1D),
        errorContainer = Color(0xFF5A2E2E),
        onErrorContainer = Color(0xFFF5D6D6),
        inverseSurface = Palette.Ink,
        inverseOnSurface = Palette.Milk,
    )

private val ThymusShapes = Shapes(
    extraSmall = RoundedCornerShape(12.dp),
    small = RoundedCornerShape(16.dp),
    medium = RoundedCornerShape(20.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

/** Applies the light or dark palette chosen by the user. */
@Composable
fun TgWsTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (ThemeState.isDark) thymusDarkColors() else thymusLightColors(),
        typography = ThymusTypography,
        shapes = ThymusShapes,
        content = content,
    )
}
