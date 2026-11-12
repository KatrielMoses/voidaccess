import { getSessionAuthorization } from "@/lib/session"
import { getBackendUrl } from "@/lib/backend";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const token = await getSessionAuthorization();

  const backendRes = await fetch(
    `${getBackendUrl()}/investigations/${(await params).id}/progress`,
    {
      headers: {
        Accept: "text/event-stream",
        ...(token ? { Authorization: token } : {}),
      },
    }
  );

  if (!backendRes.ok || !backendRes.body) {
    return new Response(null, { status: backendRes.status });
  }

  return new Response(backendRes.body, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}
