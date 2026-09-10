// Only CI downloads policy data. The extension keeps its bundled offline snapshot.
export async function downloadPolicy(url, maxBytes = 1024 * 1024) {
  if (new URL(url).protocol !== "https:") throw new Error("Policy source must use HTTPS");
  const response = await fetch(url, { signal: AbortSignal.timeout(30000), redirect: "error" });
  if (!response.ok) throw new Error(`Policy download failed (${response.status}): ${url}`);
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > maxBytes) throw new Error(`Policy download exceeds ${maxBytes} bytes`);
    chunks.push(chunk);
  }
  if (!size) throw new Error("Empty policy download");
  return Buffer.concat(chunks);
}
