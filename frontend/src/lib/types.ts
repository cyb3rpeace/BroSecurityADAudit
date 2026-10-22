export type Lang = "ru" | "en"
export type Theme = "dark" | "light" | "cyber"
export type View =
  | "overview"
  | "incidents"
  | "accounts"
  | "paths"
  | "devices"
  | "reports"
  | "docs"
  | "scan"
  | "notices"
  | "settings"
  | "assistant"
  | "notes"
  | "catalog"
  | "profile"
  | "security"

export type Me = {
  username: string
  role: string
  full_name: string
  company_id: number | null
  is_superadmin: boolean
  version?: string
}

export type Notice = {
  id: number
  title: string
  body: string
  kind: string
  at: string
  read: boolean
}

export type AuditRow = {
  id: number
  at: string
  username: string
  action: string
  detail: string
  company_id: number | null
}

export type ScanRow = {
  id: number
  module: string
  target_dc: string
  status: string
  started_at: string
  finished_at: string
  summary: string
  risk_score: number | null
  actor: string
}

export type ConsoleUser = {
  id: number
  username: string
  full_name: string
  role: string
  company_id: number | null
}

export type Company = {
  id: number
  name: string
  domain: string
  dc_host: string
  dc_user: string
  dc_password_set: boolean
  transport: string
  winrm_port: number
  ssh_port: number
  ldap_port: number
  directory_mode: string
  windows_mode: string
  runner_host: string
  scan_hosts: string
  notify_email: string
  telegram_chat: string
  schedule: string
  scheduler_enabled: boolean
  risk_index: number
}

export type Finding = {
  id: number
  hostname: string
  category: string
  title: string
  severity: string
  severity_label: string
  detail: string
  tags: string
  vuln_id: string
  mitre: string
  tactic: string
  impact: string
  detected_at: string
  status: string
}

export type TimelinePoint = { label: string; score: number; scan_id: number; when?: string; module?: string; kind?: string; actor?: string }

export type DirectoryLink = {
  ok: boolean
  domain: string
  host: string
  mode: string
  port: number
  detail: string
  checked_at: string
}
export type MitreChip = { tactic: string; count: number }
export type SliceItem = {
  title?: string
  hostname?: string
  detail?: string
  severity?: string
  vuln_id?: string
}
export type Compare = {
  ready: boolean
  message?: string
  left?: { id: number; label: string; score: number | null }
  right?: { id: number; label: string; score: number | null }
  added: SliceItem[]
  removed: SliceItem[]
}
export type Scheduler = { enabled: boolean; interval: string; next_run: string | null; label: string }
export type Remedy = {
  title: string
  summary: string
  steps: string[]
  powershell: string
  cis: string
  gost: string
  mitre: string
  tactic: string
  technique: string
  impact: string
  closure: string
}
export type WikiItem = {
  id?: string
  title: string
  text: string
  g: string
  family?: string
  what?: string
  impact?: string
  fix?: string
  sev?: string
}
export type Filters = {
  q: string
  sev: string
  status: string
  category: string
  source: string
  tactic: string
}
