export async function downloadFile(url: string, body: unknown, fallback: string) {
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    const data = await response.json().catch(() => ({}))
    const detail = typeof data.detail === "string" ? data.detail : "Файл не собран"
    throw new Error(detail)
  }
  const blob = await response.blob()
  const header = response.headers.get("Content-Disposition") || ""
  const match = /filename\*=UTF-8''([^;]+)/.exec(header)
  const name = match ? decodeURIComponent(match[1]) : fallback
  const link = document.createElement("a")
  link.href = URL.createObjectURL(blob)
  link.download = name
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(link.href)
}
