import { describe, expect, it } from "vitest";
import http from "node:http";
import { safeFetch, SsrfBlockedError } from "../src/net/safeFetch.js";

function startServer(handler: http.RequestListener): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

describe("safeFetch - ochrona SSRF", () => {
  it("domyslnie blokuje polaczenia do loopback (127.0.0.1)", async () => {
    const { url, close } = await startServer((_req, res) => res.end("ok"));
    try {
      await expect(safeFetch(url)).rejects.toThrow(SsrfBlockedError);
    } finally {
      await close();
    }
  });

  it("blokuje niedozwolone protokoly (np. file:)", async () => {
    await expect(safeFetch("file:///etc/passwd")).rejects.toThrow(SsrfBlockedError);
  });

  it("z allowPrivateNetworks=true (tylko do testow) pozwala pobrac z lokalnego serwera", async () => {
    const { url, close } = await startServer((_req, res) => res.end("hello from test server"));
    try {
      const result = await safeFetch(url, { allowPrivateNetworks: true });
      expect(result.status).toBe(200);
      expect(result.body.toString("utf8")).toBe("hello from test server");
    } finally {
      await close();
    }
  });

  it("obsluguje przekierowania i ponownie waliduje kazdy hop", async () => {
    const target = await startServer((_req, res) => res.end("final destination"));
    const redirector = await startServer((_req, res) => {
      res.writeHead(302, { Location: target.url });
      res.end();
    });
    try {
      const result = await safeFetch(redirector.url, { allowPrivateNetworks: true });
      expect(result.body.toString("utf8")).toBe("final destination");
      expect(result.finalUrl).toBe(target.url + "/");
    } finally {
      await redirector.close();
      await target.close();
    }
  });

  it("limituje rozmiar odpowiedzi", async () => {
    const { url, close } = await startServer((_req, res) => {
      res.end("x".repeat(1000));
    });
    try {
      await expect(safeFetch(url, { allowPrivateNetworks: true, maxBodyBytes: 100 })).rejects.toThrow();
    } finally {
      await close();
    }
  });
});
