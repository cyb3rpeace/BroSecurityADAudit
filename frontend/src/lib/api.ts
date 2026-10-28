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
    const detail = typeof data.detail === "string" ? data.detail : "Запрос отклонен"
    throw new ApiError(response.status, detail)
  }
  return data as T
}
