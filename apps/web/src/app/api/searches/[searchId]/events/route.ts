import { type NextRequest } from "next/server";

// Edge runtime uses the Web Streams API natively — no buffering of SSE chunks.
export const runtime = "edge";

const API_ORIGIN = process.env.API_URL ?? "http://localhost:4000";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ searchId: string }> }
) {
  const { searchId } = await params;

  // Forward the cookie from the browser so the upstream API can authenticate.
  const upstream = await fetch(`${API_ORIGIN}/searches/${searchId}/events`, {
    headers: {
      cookie: req.headers.get("cookie") ?? "",
      accept: "text/event-stream",
      "cache-control": "no-cache",
    },
  });

  if (!upstream.ok || !upstream.body) {
    return new Response(upstream.body, { status: upstream.status });
  }

  // Stream the SSE response body directly — no buffering, unlike rewrites().
  return new Response(upstream.body, {
    status: 200,
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    },
  });
}
