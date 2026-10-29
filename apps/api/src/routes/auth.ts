import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { withAppContext, serviceContext, userContext, type UserRole } from "@unified-osint/core";
import { hashPassword, verifyPassword } from "../auth/password.js";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../auth/jwt.js";
import { durationToSeconds } from "../util/duration.js";

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(10, "Haslo musi miec co najmniej 10 znakow"),
  displayName: z.string().min(1).max(200),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  display_name: string;
  role: UserRole;
  disabled_at: string | null;
}

export async function authRoutes(app: FastifyInstance): Promise<void> {
  const { env, pool } = app.appContext;
  const accessTtlSeconds = durationToSeconds(env.JWT_ACCESS_TTL);
  const refreshTtlSeconds = durationToSeconds(env.JWT_REFRESH_TTL);
  const cookieSecure = env.NODE_ENV === "production";
  const cookieSameSite: "lax" | "strict" = env.NODE_ENV === "production" ? "strict" : "lax";

  function setSessionCookies(reply: import("fastify").FastifyReply, accessToken: string, refreshToken: string): void {
    reply.setCookie("access_token", accessToken, {
      httpOnly: true,
      sameSite: cookieSameSite,
      secure: cookieSecure,
      path: "/",
      maxAge: accessTtlSeconds,
    });
    reply.setCookie("refresh_token", refreshToken, {
      httpOnly: true,
      sameSite: cookieSameSite,
      secure: cookieSecure,
      path: "/",
      maxAge: refreshTtlSeconds,
    });
  }

  app.post("/auth/register", async (request, reply) => {
    const body = registerSchema.parse(request.body);
    const existing = await withAppContext(pool, serviceContext(), (client) =>
      client.query<{ id: string }>("select id from users where email = $1", [body.email.toLowerCase()])
    );
    if (existing.rows.length > 0) {
      reply.code(409).send({ error: "email_taken", message: "Konto z tym adresem e-mail juz istnieje" });
      return;
    }

    const passwordHash = await hashPassword(body.password, env.AUTH_ARGON2_MEMORY_KB);
    const user = await withAppContext(pool, serviceContext(), (client) =>
      client.query<UserRow>(
        `insert into users (email, password_hash, display_name, role)
         values ($1, $2, $3, 'viewer')
         returning id, email, password_hash, display_name, role, disabled_at`,
        [body.email.toLowerCase(), passwordHash, body.displayName]
      )
    );
    const row = user.rows[0]!;

    const accessToken = signAccessToken({ sub: row.id, role: row.role }, env.JWT_ACCESS_SECRET, env.JWT_ACCESS_TTL);
    const refreshToken = signRefreshToken(
      { sub: row.id, role: row.role, jti: crypto.randomUUID() },
      env.JWT_REFRESH_SECRET,
      env.JWT_REFRESH_TTL
    );
    setSessionCookies(reply, accessToken, refreshToken);
    reply.code(201).send({ id: row.id, email: row.email, displayName: row.display_name, role: row.role });
  });

  app.post("/auth/login", async (request, reply) => {
    const body = loginSchema.parse(request.body);
    const result = await withAppContext(pool, serviceContext(), (client) =>
      client.query<UserRow>(
        "select id, email, password_hash, display_name, role, disabled_at from users where email = $1",
        [body.email.toLowerCase()]
      )
    );
    const row = result.rows[0];
    // Stala odpowiedz niezaleznie od tego, czy e-mail istnieje - bez wyciekania, ktore konta sa zarejestrowane.
    const invalidCredentials = () => reply.code(401).send({ error: "invalid_credentials", message: "Nieprawidlowy e-mail lub haslo" });

    if (!row || row.disabled_at) {
      invalidCredentials();
      return;
    }
    const ok = await verifyPassword(body.password, row.password_hash);
    if (!ok) {
      invalidCredentials();
      return;
    }

    const accessToken = signAccessToken({ sub: row.id, role: row.role }, env.JWT_ACCESS_SECRET, env.JWT_ACCESS_TTL);
    const refreshToken = signRefreshToken(
      { sub: row.id, role: row.role, jti: crypto.randomUUID() },
      env.JWT_REFRESH_SECRET,
      env.JWT_REFRESH_TTL
    );
    setSessionCookies(reply, accessToken, refreshToken);
    reply.send({ id: row.id, email: row.email, displayName: row.display_name, role: row.role });
  });

  app.post("/auth/auto-login", async (request, reply) => {
    // Tryb jednego konta: loguje bez hasla, ale tylko gdy w systemie jest
    // dokladnie jeden uzytkownik - w przeciwnym razie frontend ma pokazac
    // normalny formularz logowania (kilka kont = nie da sie wybrac ktore).
    const result = await withAppContext(pool, serviceContext(), (client) =>
      client.query<UserRow>(
        "select id, email, password_hash, display_name, role, disabled_at from users where disabled_at is null"
      )
    );
    if (result.rows.length !== 1) {
      reply.code(403).send({
        error: "auto_login_unavailable",
        message: "Automatyczne logowanie dziala tylko przy dokladnie jednym koncie",
      });
      return;
    }
    const row = result.rows[0]!;

    const accessToken = signAccessToken({ sub: row.id, role: row.role }, env.JWT_ACCESS_SECRET, env.JWT_ACCESS_TTL);
    const refreshToken = signRefreshToken(
      { sub: row.id, role: row.role, jti: crypto.randomUUID() },
      env.JWT_REFRESH_SECRET,
      env.JWT_REFRESH_TTL
    );
    setSessionCookies(reply, accessToken, refreshToken);
    reply.send({ id: row.id, email: row.email, displayName: row.display_name, role: row.role });
  });

  app.post("/auth/refresh", async (request, reply) => {
    const token = request.cookies["refresh_token"];
    if (!token) {
      reply.code(401).send({ error: "unauthorized", message: "Brak refresh tokenu" });
      return;
    }
    try {
      const payload = verifyRefreshToken(token, env.JWT_REFRESH_SECRET);
      const accessToken = signAccessToken({ sub: payload.sub, role: payload.role }, env.JWT_ACCESS_SECRET, env.JWT_ACCESS_TTL);
      const refreshToken = signRefreshToken(
        { sub: payload.sub, role: payload.role, jti: crypto.randomUUID() },
        env.JWT_REFRESH_SECRET,
        env.JWT_REFRESH_TTL
      );
      setSessionCookies(reply, accessToken, refreshToken);
      reply.send({ ok: true });
    } catch {
      reply.code(401).send({ error: "unauthorized", message: "Refresh token nieprawidlowy lub wygasly" });
    }
  });

  app.post("/auth/logout", async (_request, reply) => {
    reply.clearCookie("access_token", { path: "/" });
    reply.clearCookie("refresh_token", { path: "/" });
    reply.send({ ok: true });
  });

  app.get("/auth/me", { preHandler: app.authenticate }, async (request, reply) => {
    const user = request.currentUser!;
    const result = await withAppContext(pool, userContext(user.id, user.role), (client) =>
      client.query<UserRow>("select id, email, display_name, role from users where id = $1", [user.id])
    );
    const row = result.rows[0];
    if (!row) {
      reply.code(404).send({ error: "not_found" });
      return;
    }
    reply.send({ id: row.id, email: row.email, displayName: row.display_name, role: row.role });
  });
}
