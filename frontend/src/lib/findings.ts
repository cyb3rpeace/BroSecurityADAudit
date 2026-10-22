import type { Compare, Finding, Theme } from "@/lib/types"

export const ACCOUNT_IDS = new Set([
  "ordinary_privileged",
  "stale_password",
  "inactive_stale",
  "guest_enabled",
  "kerberoasting",
  "asrep_preauth",
  "priv_password_never_expires",
  "not_in_protected_users",
  "honeytoken",
  "gpp_password",
  "password_length",
  "password_history",
  "no_lockout",
  "reversible_encryption",
  "password_not_required",
  "password_in_description",
  "des_enabled",
  "rc4_only",
  "sid_history",
  "pre_windows_2000",
  "foreign_privileged",
  "exchange_permissions",
  "weak_pso",
  "empty_security_group",
  "large_group",
  "deep_group_nesting",
  "circular_group_nesting",
])
export const DEVICE_IDS = new Set([
  "obsolete_os",
  "anydesk_detected",
  "teamviewer_detected",
  "rustdesk_detected",
  "vnc_detected",
  "vpn_unauthorized",
  "remote_access_detected",
  "rat_detected",
  "active_smbv1",
  "print_spooler_on_dc",
  "time_skew",
  "time_ok",
  "stale_computer",
  "single_dc",
  "orphan_subnet",
  "ntfrs_sysvol",
  "laps_gap",
  "machine_password_old",
  "fsmo_single_host",
  "empty_ou",
  "dns_wildcard",
  "webclient_running",
])
export const PATH_IDS = new Set([
  "kerberoasting",
  "unconstrained_delegation",
  "asrep_preauth",
  "adcs_enrollee_san",
  "constrained_delegation",
  "rbcd",
  "shadow_credential",
  "machine_quota",
])

const SOURCE_NAMES: Record<string, string> = {
  protocols: "Протоколы",
  baseline: "Базовый профиль",
  bloodhound: "BloodHound",
  baseline_hygiene: "Гигиена каталога",
  trusts: "Доверия",
  time_sync: "Время",
  dc_hardening: "Харденинг",
  software_audit: "Аудит ПО",
  gpp_passwords: "Пароли в GPO",
  ad_cs: "AD CS",
  honeytoken: "Ловушки",
}

const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export function rank(row: Finding) {
  return RANK[row.severity] ?? 5
}

export function incidentsOf(rows: Finding[]) {
  return rows.filter((row) => row.severity !== "info")
}

export function isAccount(row: Finding) {
  return ACCOUNT_IDS.has(row.vuln_id)
}

export function isDevice(row: Finding) {
  return DEVICE_IDS.has(row.vuln_id) || (row.tags || "").includes("shadow_it")
}

export function isPath(row: Finding) {
  return PATH_IDS.has(row.vuln_id) || (row.tags || "").includes("bloodhound")
}

export function sourceName(row: Finding) {
  const found = String(row.tags || "").match(/module:([a-z0-9_]+)/)
  if (found) return SOURCE_NAMES[found[1]] || found[1]
  return row.category || "Прочее"
}

export function matchesQuery(row: Finding, query: string) {
  const q = query.trim().toLowerCase()
  if (!q) return true
  return [row.hostname, row.category, row.title, row.detail, row.tags].join(" ").toLowerCase().includes(q)
}

export function statuses(): Record<string, string> {
  try {
    return JSON.parse(localStorage.getItem("brosec-status") || "{}") as Record<string, string>
  } catch {
    return {}
  }
}

export function rowStatus(row: Finding) {
  return statuses()[String(row.id)] || "open"
}

export function cycleStatus(id: number) {
  const order = ["open", "investigating", "closed"]
  const all = statuses()
  const now = all[String(id)] || "open"
  all[String(id)] = order[(order.indexOf(now) + 1) % order.length]
  localStorage.setItem("brosec-status", JSON.stringify(all))
}

export function palette(theme: Theme) {
  if (theme === "light") {
    return {
      line: "#14b8a6",
      donut: ["#ef4444", "#f59e0b", "#3b82f6", "#10b981"],
      bar: ["#14b8a6", "#38bdf8", "#6366f1", "#f59e0b", "#ef4444"],
    }
  }
  if (theme === "cyber") {
    return {
      line: "#e14bff",
      donut: ["#ff3b5c", "#ff9f1a", "#b44cff", "#2ee59d"],
      bar: ["#ff9f1a", "#3ecbff", "#e14bff", "#2ee59d", "#ff3b5c"],
    }
  }
  return {
    line: "#fafafa",
    donut: ["#ff3b5c", "#ff9f1a", "#7c5cff", "#2ee59d"],
    bar: ["#fafafa", "#a1a1aa", "#ff9f1a", "#3ecbff", "#e14bff"],
  }
}

export function sevColor(theme: Theme, severity: string) {
  const colors = palette(theme).donut
  const index = ["critical", "high", "medium", "low"].indexOf(severity)
  return index >= 0 ? colors[index] : "#a1a1aa"
}

export function deltaOf(compare: Compare | null, pred: (row: SliceLike) => boolean) {
  if (!compare?.ready) return null
  return compare.added.filter(pred).length - compare.removed.filter(pred).length
}

type SliceLike = { severity?: string; vuln_id?: string }

export function driftText(now: number, delta: number | null, empty: string) {
  if (delta === null) return empty
  const prev = now - delta
  if (!prev) return (delta > 0 ? "+" : "") + delta
  const pct = Math.round((delta / prev) * 100)
  return (pct > 0 ? "+" : "") + pct + "%"
}

export function countBy(rows: Finding[], keyOf: (row: Finding) => string) {
  const map: Record<string, number> = {}
  rows.forEach((row) => {
    const key = keyOf(row)
    map[key] = (map[key] || 0) + 1
  })
  return Object.entries(map).map(([name, value]) => ({ name, value }))
}
