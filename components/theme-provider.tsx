"use client"

import * as React from "react"

type Theme = "light" | "dark" | "system"

type ThemeContextValue = {
  theme: Theme
  resolvedTheme: "light" | "dark"
  setTheme: (theme: Theme) => void
  toggle: () => void
}

const ThemeContext = React.createContext<ThemeContextValue | null>(null)

const STORAGE_KEY = "insta-p8-theme"

/**
 * Apply the resolved theme to <html>. We toggle the .dark class and set
 * the color-scheme meta so native form controls (scrollbars, inputs) follow.
 */
function applyTheme(resolved: "light" | "dark") {
  if (typeof document === "undefined") return
  const root = document.documentElement

  // Temporarily disable CSS transitions on all elements so theme colors, borders,
  // and surfaces update atomically in a single frame without lingering transitions.
  const style = document.createElement("style")
  style.appendChild(
    document.createTextNode(
      `*, *::before, *::after {
        -webkit-transition: none !important;
        -moz-transition: none !important;
        -o-transition: none !important;
        -ms-transition: none !important;
        transition: none !important;
      }`
    )
  )
  document.head.appendChild(style)

  root.classList.toggle("dark", resolved === "dark")
  root.style.colorScheme = resolved
  root.dataset.theme = resolved

  // Force reflow to commit new theme styles synchronously with transitions disabled
  void window.getComputedStyle(style).opacity

  // Re-enable transitions in the next frame so hover states work normally
  requestAnimationFrame(() => {
    try {
      if (style.parentNode) {
        style.parentNode.removeChild(style)
      }
    } catch {}
  })
}

function getSystemTheme(): "light" | "dark" {
  if (typeof window === "undefined") return "light"
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
}

function resolveTheme(theme: Theme): "light" | "dark" {
  return theme === "system" ? getSystemTheme() : theme
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = React.useState<Theme>("dark")
  const [resolvedTheme, setResolvedTheme] = React.useState<"light" | "dark">("dark")
  const [mounted, setMounted] = React.useState(false)

  // Read stored theme on first mount and apply it before paint
  React.useLayoutEffect(() => {
    let initial: Theme = "dark"
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY) as Theme | null
      if (stored === "light" || stored === "dark" || stored === "system") {
        initial = stored
      }
    } catch {
      // localStorage unavailable (e.g. SSR or sandboxed) — fall back to dark
    }
    const resolved = resolveTheme(initial)
    applyTheme(resolved)
    setThemeState(initial)
    setResolvedTheme(resolved)
    setMounted(true)
  }, [])

  // Follow OS changes when theme === "system"
  React.useEffect(() => {
    if (theme !== "system") return
    const mq = window.matchMedia("(prefers-color-scheme: dark)")
    const onChange = () => {
      const resolved = getSystemTheme()
      applyTheme(resolved)
      setResolvedTheme(resolved)
    }
    mq.addEventListener("change", onChange)
    return () => mq.removeEventListener("change", onChange)
  }, [theme])

  const setTheme = React.useCallback((next: Theme) => {
    const resolved = resolveTheme(next)
    applyTheme(resolved)
    setThemeState(next)
    setResolvedTheme(resolved)
    try {
      window.localStorage.setItem(STORAGE_KEY, next)
    } catch {}
  }, [])

  const toggle = React.useCallback(() => {
    setTheme(resolvedTheme === "dark" ? "light" : "dark")
  }, [resolvedTheme, setTheme])

  const value = React.useMemo(
    () => ({ theme, resolvedTheme, setTheme, toggle }),
    [theme, resolvedTheme, setTheme, toggle],
  )

  // Avoid hydration mismatch: until mounted, children render with the server theme.
  // We rely on the no-FOUC inline script in <head> to keep things stable pre-hydration.
  return (
    <ThemeContext.Provider value={value}>
      <span data-theme-mounted={mounted ? "true" : "false"} className="contents">
        {children}
      </span>
    </ThemeContext.Provider>
  )
}

export function useTheme(): ThemeContextValue {
  const ctx = React.useContext(ThemeContext)
  if (!ctx) {
    throw new Error("useTheme must be used inside <ThemeProvider>")
  }
  return ctx
}