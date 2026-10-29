/** @type {import('next').NextConfig} */
const API_URL = process.env.API_URL ?? "http://localhost:4000";

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    // Route Handlers in app/api/ take priority over these afterFiles rewrites.
    // SSE is handled by app/api/searches/[searchId]/events/route.ts (streaming).
    return [
      {
        source: "/api/:path*",
        destination: `${API_URL}/:path*`,
      },
    ];
  },
};

export default nextConfig;
