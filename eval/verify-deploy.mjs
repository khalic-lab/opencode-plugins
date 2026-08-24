#!/usr/bin/env node
/**
 * Compare the files in this repo with the copies opencode actually loads.
 *
 * The tested file and the running file are different files: `file://` plugin
 * entries outside ~/.config/opencode are ignored and symlinks do not load, so
 * deployment is a manual `cp` and drift is invisible until something behaves
 * unlike its tests. This makes the drift loud.
 *
 * Three files ship, not one: the server plugin that classifies, and the TUI
 * plugin that draws the box plus the module it gets its words from. They are
 * registered in different config files and a stale copy of any of them looks
 * like a bug in the others.
 *
 * Usage: node eval/verify-deploy.mjs [deploy-dir]
 * Exit 0 all identical, 1 if any differ or are missing.
 */

import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import crypto from "node:crypto"
import { fileURLToPath } from "node:url"

const here = path.dirname(fileURLToPath(import.meta.url))
const repoDir = path.join(here, "..", "packages", "local-classifier")
const deployDir = process.argv[2] ?? path.join(os.homedir(), ".config", "opencode", "local-classifier")
const FILES = ["local-classifier.js", "local-classifier-tui.tsx", "tui-view.js"]

const sha = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")

let bad = 0
for (const name of FILES) {
  const source = path.join(repoDir, name)
  const deployed = path.join(deployDir, name)

  let srcHash
  try {
    srcHash = sha(source)
  } catch (e) {
    console.error(`cannot read repo file ${source}: ${e.message}`)
    bad++
    continue
  }

  let deployedHash
  try {
    deployedHash = sha(deployed)
  } catch {
    console.error(`NOT DEPLOYED: ${deployed} is missing`)
    console.error(`  cp ${source} ${deployed}`)
    bad++
    continue
  }

  if (srcHash === deployedHash) {
    console.log(`in sync: ${name}  sha256 ${srcHash.slice(0, 16)}…`)
    continue
  }

  console.error(`DRIFT: ${name} — the running file is not the tested one`)
  console.error(`  repo     ${srcHash.slice(0, 16)}…  ${source}`)
  console.error(`  deployed ${deployedHash.slice(0, 16)}…  ${deployed}`)
  console.error(`  cp ${source} ${deployed}`)
  bad++
}

// A copied file that nothing registers is as dead as a missing one, and it
// fails the same silent way: one line in ~/.local/share/opencode/log/opencode.log
// and no plugin. The two kinds are read from two different config files.
const registrations = [
  { file: "opencode.json", name: "local-classifier.js", kind: "server" },
  { file: "tui.json", name: "local-classifier-tui.tsx", kind: "tui" },
]
for (const { file, name, kind } of registrations) {
  const configPath = path.join(deployDir, "..", file)
  const target = path.join(deployDir, name)
  let entries
  try {
    entries = JSON.parse(fs.readFileSync(configPath, "utf8")).plugin
  } catch (e) {
    console.error(`NOT REGISTERED: cannot read ${configPath} (${e.message})`)
    console.error(`  the ${kind} plugin will not load, with one log line to say so`)
    bad++
    continue
  }
  // An entry is either a bare spec or a [spec, options] tuple.
  const specs = (Array.isArray(entries) ? entries : []).map((e) => (Array.isArray(e) ? e[0] : e))
  const hit = specs.some((spec) => typeof spec === "string" && spec.replace(/^file:\/\//, "") === target)
  if (hit) {
    console.log(`registered: ${name} in ${file}`)
    continue
  }
  console.error(`NOT REGISTERED: ${file} has no entry for ${target}`)
  console.error(`  add "file://${target}" to its "plugin" array`)
  bad++
}

if (bad > 0) {
  // Counted as problems, not as files: a registration failure is not a file
  // that drifted, and calling it one sends you looking in the wrong place.
  console.error(`${bad} problem(s) above — fix them, then restart opencode`)
  process.exit(1)
}
process.exit(0)
