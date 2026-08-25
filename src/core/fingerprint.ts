export function normalizeSha256(value: string): string | null {
  const normalized = value.toLowerCase().replace(/[:\s]/g, "");
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes).buffer);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
