import { setDefaultAutoSelectFamilyAttemptTimeout } from "node:net";
import { setTimeout } from "node:timers/promises";

// Cross-region runners need more than Node's short per-address connection window.
setDefaultAutoSelectFamilyAttemptTimeout(3000);

const transientCodes = new Set([
  "ETIMEDOUT", "ECONNRESET", "ECONNREFUSED", "EAI_AGAIN", "ENETUNREACH", "EHOSTUNREACH",
  "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT", "UND_ERR_SOCKET"
]);
const transientStatuses = new Set([408, 429, 500, 502, 503, 504]);
function isTransient(error) {
  return error && (error.name === "TimeoutError" || transientCodes.has(error.code) ||
    transientStatuses.has(error.status) || error.errors?.some(isTransient) || isTransient(error.cause));
}

// Only CI downloads policy data. The extension keeps its bundled offline snapshot.
export async function downloadPolicy(url, maxBytes = 1024 * 1024) {
  if (new URL(url).protocol !== "https:") throw new Error("Policy source must use HTTPS");
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(30000), redirect: "error" });
      if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        throw Object.assign(new Error(`Policy download failed (${response.status}): ${url}`), { status: response.status });
      }
      const chunks = [];
      let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > maxBytes) throw new Error(`Policy download exceeds ${maxBytes} bytes`);
        chunks.push(chunk);
      }
      if (!size) throw new Error("Empty policy download");
      return Buffer.concat(chunks);
    } catch (error) {
      if (attempt === 3 || !isTransient(error)) throw error;
      console.warn(`Policy download attempt ${attempt}/3 failed for ${url}: ${error.cause?.code || error.code || error.message}; retrying`);
      await setTimeout(attempt * 1000);
    }
  }
}
