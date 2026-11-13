import { afterEach, describe, expect, it, vi } from "vitest";
import { downloadPolicy } from "../scripts/download-policy.mjs";

vi.mock("node:timers/promises", () => ({ setTimeout: vi.fn(async () => {}) }));
import { setTimeout } from "node:timers/promises";

const url = "https://example.test/policy";
const networkError = (code) => new TypeError("fetch failed", {
  cause: new AggregateError([Object.assign(new Error("connect failed"), { code })])
});
afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks(); });

describe("policy source downloads", () => {
  it.each(["ETIMEDOUT", "ENETUNREACH", "EAI_AGAIN", "ECONNRESET"])("recovers from %s without changing the source or redirect policy", async (code) => {
    const fetch = vi.fn().mockRejectedValueOnce(networkError(code)).mockResolvedValueOnce(new Response("policy"));
    vi.stubGlobal("fetch", fetch);
    expect((await downloadPolicy(url)).toString()).toBe("policy");
    expect(fetch).toHaveBeenCalledTimes(2);
    for (const [source, options] of fetch.mock.calls) {
      expect(source).toBe(url);
      expect(options.redirect).toBe("error");
      expect(options.signal).toBeInstanceOf(AbortSignal);
    }
    expect(setTimeout).toHaveBeenCalledWith(1000);
  });

  it.each([408, 429, 500, 502, 503, 504])("retries HTTP %s and discards its body", async (status) => {
    const response = new Response("unavailable", { status });
    const fetch = vi.fn().mockResolvedValueOnce(response).mockResolvedValueOnce(new Response("policy"));
    vi.stubGlobal("fetch", fetch);
    expect((await downloadPolicy(url)).toString()).toBe("policy");
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(response.bodyUsed).toBe(true);
  });

  it("stops after three failed attempts and preserves the error", async () => {
    const error = networkError("ETIMEDOUT");
    const fetch = vi.fn().mockRejectedValue(error);
    vi.stubGlobal("fetch", fetch);
    await expect(downloadPolicy(url)).rejects.toBe(error);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(setTimeout.mock.calls).toEqual([[1000], [2000]]);
  });

  it("discards a partial response before retrying a body timeout", async () => {
    let first = true;
    const body = new ReadableStream({ pull(controller) {
      if (first) { first = false; controller.enqueue(Buffer.from("partial")); }
      else controller.error(new DOMException("Timed out", "TimeoutError"));
    } });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(body)).mockResolvedValueOnce(new Response("complete")));
    expect((await downloadPolicy(url)).toString()).toBe("complete");
  });

  it.each([
    [() => Promise.reject(networkError("CERT_HAS_EXPIRED")), "fetch failed"],
    [() => Promise.reject(new TypeError("redirect count exceeded")), "redirect"],
    [() => new Response("denied", { status: 403 }), "403"],
    [() => new Response(""), "Empty policy download"],
    [() => new Response("oversized"), "exceeds 4 bytes"]
  ])("rejects permanent failures and invalid downloads without retrying (%#)", async (response, message) => {
    const fetch = vi.fn(response);
    vi.stubGlobal("fetch", fetch);
    await expect(downloadPolicy(url, 4)).rejects.toThrow(message);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(setTimeout).not.toHaveBeenCalled();
  });

  it("rejects insecure sources before making a request", async () => {
    const fetch = vi.fn(); vi.stubGlobal("fetch", fetch);
    await expect(downloadPolicy("http://example.test/policy")).rejects.toThrow("HTTPS");
    expect(fetch).not.toHaveBeenCalled();
  });
});
