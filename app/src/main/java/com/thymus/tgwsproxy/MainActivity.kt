package com.thymus.tgwsproxy

import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.LaunchedEffect
import com.thymus.tgwsproxy.data.Settings
import com.thymus.tgwsproxy.ui.HomeScreen
import com.thymus.tgwsproxy.ui.TgWsTheme
import com.thymus.tgwsproxy.ui.ThemeMode
import com.thymus.tgwsproxy.ui.ThemeState

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ThemeState.set(if (Settings.isDarkTheme(this)) ThemeMode.DARK else ThemeMode.LIGHT)
        setContent {
            val dark = ThemeState.isDark
            // The bars sit on top of the botanical background, so the icon colour has to
            // follow the theme: dark icons on the lavender day art, light on the night art.
            LaunchedEffect(dark) {
                this@MainActivity.enableEdgeToEdge(
                    statusBarStyle = barStyle(dark),
                    navigationBarStyle = barStyle(dark),
                )
            }
            TgWsTheme {
                HomeScreen()
            }
        }
    }

    private fun barStyle(dark: Boolean): SystemBarStyle =
        if (dark) {
            SystemBarStyle.dark(Color.TRANSPARENT)
        } else {
            SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
        }
}
