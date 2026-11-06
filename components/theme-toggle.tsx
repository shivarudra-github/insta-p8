"use client"

import { useRef } from "react"
import { Moon, Sun } from "lucide-react"
import { flushSync } from "react-dom"
import { useTheme } from "@/components/theme-provider"
import { cn } from "@/lib/utils"

/**
 * Pill toggle for light/dark theme. Surfaces current state and the next
 * action via label and aria-label so it's usable without color cues.
 *
 * Color contrast:
 *   - track border uses --border (≥3:1 on background)
 *   - thumb uses --card + --card-foreground (≥4.5:1)
 *   - icons inside thumb pick the matching foreground token
 */
export function ThemeToggle({ className }: { className?: string }) {
  const { resolvedTheme, toggle } = useTheme()
  const isDark = resolvedTheme === "dark"

  const isTransitioningRef = useRef(false)

  const handleToggle = (event: React.MouseEvent<HTMLButtonElement>) => {
    if (isTransitioningRef.current) return

    // Fall back to immediate toggle if reduced motion is preferred or View Transitions API is unavailable
    const isReduced = typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches
    const doc = typeof document !== "undefined" ? (document as Document & {
      startViewTransition?: (callback: () => Promise<void> | void) => {
        ready: Promise<void>
        finished: Promise<void>
      }
    }) : null

    if (!doc?.startViewTransition || isReduced) {
      toggle()
      return
    }

    isTransitioningRef.current = true

    const rect = event.currentTarget.getBoundingClientRect()
    const x = event.clientX || rect.left + rect.width / 2
    const y = event.clientY || rect.top + rect.height / 2
    const endRadius = Math.hypot(
      Math.max(x, window.innerWidth - x),
      Math.max(y, window.innerHeight - y)
    )

    const transition = doc.startViewTransition(() => {
      flushSync(() => {
        toggle()
      })
    })

    transition.ready
      .then(() => {
        const animation = document.documentElement.animate(
          {
            clipPath: [
              `circle(0px at ${x}px ${y}px)`,
              `circle(${endRadius}px at ${x}px ${y}px)`,
            ],
          },
          {
            duration: 380,
            easing: "cubic-bezier(0.4, 0, 0.2, 1)",
            pseudoElement: "::view-transition-new(root)",
          }
        )
        return animation.finished
      })
      .catch(() => {
        // Fallback: If view transition animation fails, theme was already toggled safely
      })
      .finally(() => {
        isTransitioningRef.current = false
      })
  }

  return (
    <button
      type="button"
      onClick={handleToggle}
      role="switch"
      aria-checked={isDark}
      aria-label={`Switch to ${isDark ? "light" : "dark"} theme`}
      title={`Switch to ${isDark ? "light" : "dark"} theme`}
      className={cn(
        "group relative inline-flex h-8 w-16 shrink-0 items-center rounded-full border border-border bg-secondary transition-colors",
        "hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
        className,
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          "pointer-events-none absolute top-1/2 -translate-y-1/2 h-6 w-6 rounded-full bg-card text-card-foreground shadow-sm border border-border transition-all duration-200 ease-out flex items-center justify-center",
          isDark ? "left-[calc(100%-1.625rem-2px)]" : "left-[2px]",
        )}
      >
        {isDark ? (
          <Moon className="h-3.5 w-3.5" aria-hidden="true" />
        ) : (
          <Sun className="h-3.5 w-3.5" aria-hidden="true" />
        )}
      </span>
      {/* Hidden but readable label for assistive tech that ignores aria-label */}
      <span className="sr-only">{isDark ? "Dark theme enabled" : "Light theme enabled"}</span>
    </button>
  )
}
