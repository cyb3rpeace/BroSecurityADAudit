export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export async function api<T>(url: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(url, { ...options, credentials: "same-origin" })
  const data = await response.json().catch(() => ({}))
  if (response.status === 401) {
    const detail = typeof data.detail === "string" ? data.detail : "auth"
    throw new ApiError(401, detail)
  }
  if (!response.ok) {
    const raw = data?.detail
    const detail = typeof raw === "string"
      ? raw
      : Array.isArray(raw)
        ? raw.map((item: unknown) => {
            if (!item || typeof item !== "object") return String(item)
            const value = item as { loc?: unknown[]; msg?: unknown }
            const location = Array.isArray(value.loc) ? value.loc.filter(Boolean).join(" → ") : "запрос"
            return `${location}: ${typeof value.msg === "string" ? value.msg : "недопустимое значение"}`
          }).join("; ") || `HTTP ${response.status}`
        : raw && typeof raw === "object" && "message" in raw
          ? String((raw as { message?: unknown }).message || `HTTP ${response.status}`)
          : `HTTP ${response.status}: запрос отклонён`
    throw new ApiError(response.status, detail)
  }
  return data as T
}
