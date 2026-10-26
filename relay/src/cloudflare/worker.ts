// Cloudflare Worker entry: hands the relay's routes to the one Lobby Durable Object, where the core does
// all auth. Anything else gets an empty 404 here, without waking the object.
export { Lobby } from "./lobby.ts";

const ROUTES = /^\/(ldn|logs|update\/.*|admin|admin\/login|api\/.*|invite\/[0-9a-f]{64})$/;

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    // (an upgrade's method does not survive the hop to the object, so it is checked here too)
    if (!ROUTES.test(new URL(req.url).pathname) || (req.headers.has("Upgrade") && req.method !== "GET")) return new Response(null, { status: 404 });
    return env.LOBBY.get(env.LOBBY.idFromName("main"), { locationHint: "enam" }).fetch(req);
  },
} satisfies ExportedHandler<Env>;
