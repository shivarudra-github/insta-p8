import { pathToFileURL, fileURLToPath } from "node:url"
import path from "node:path"
import fs from "node:fs"

const rootDir = process.cwd()

export async function resolve(specifier, context, nextResolve) {
  if (specifier === "next/server") {
    return nextResolve("next/server.js", context)
  }

  if (specifier === "next/headers") {
    return nextResolve("next/headers.js", context)
  }

  if (specifier === "next/navigation") {
    return nextResolve("next/navigation.js", context)
  }

  if (specifier === "@/lib/supabase-server") {
    const mockFile = path.resolve(rootDir, "tests/supabase-mock.ts")
    return nextResolve(pathToFileURL(mockFile).href, context)
  }

  if (specifier.startsWith("@/")) {
    const rel = specifier.slice(2)
    const resolvedPath = path.resolve(rootDir, rel)

    for (const ext of ["", ".ts", ".tsx", ".js", ".mjs"]) {
      const full = resolvedPath + ext
      if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        return nextResolve(pathToFileURL(full).href, context)
      }
    }
  }

  // Handle extensionless relative imports (e.g. "./supabase-admin" -> "./supabase-admin.ts")
  if (specifier.startsWith("./") || specifier.startsWith("../")) {
    const parentDir = context.parentURL ? path.dirname(fileURLToPath(context.parentURL)) : rootDir
    const resolvedPath = path.resolve(parentDir, specifier)

    for (const ext of [".ts", ".tsx", ".js", ".mjs"]) {
      const full = resolvedPath + ext
      if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        return nextResolve(pathToFileURL(full).href, context)
      }
    }
  }

  return nextResolve(specifier, context)
}
