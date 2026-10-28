import fp from "fastify-plugin";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { UserRole } from "@unified-osint/core";
import { verifyAccessToken } from "./jwt.js";

declare module "fastify" {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
  interface FastifyRequest {
    currentUser?: { id: string; role: UserRole };
  }
}

/**
 * Dekoruje fastify instancje preHandlerem `authenticate`, uzywanym jawnie
 * (`{ preHandler: app.authenticate }`) na trasach wymagajacych sesji -
 * czytelniej niz globalny onRequest hook dla calej aplikacji.
 */
export const authPlugin = fp(async function authPlugin(app: FastifyInstance) {
  app.decorate("authenticate", async (request: FastifyRequest, reply: FastifyReply) => {
    const token = request.cookies["access_token"];
    if (!token) {
      reply.code(401).send({ error: "unauthorized", message: "Brak tokenu dostepu" });
      return;
    }
    try {
      const payload = verifyAccessToken(token, app.appContext.env.JWT_ACCESS_SECRET);
      request.currentUser = { id: payload.sub, role: payload.role };
    } catch {
      reply.code(401).send({ error: "unauthorized", message: "Token nieprawidlowy lub wygasly" });
    }
  });
});
