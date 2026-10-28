import jwt from "jsonwebtoken";
import type { UserRole } from "@unified-osint/core";
import { durationToSeconds } from "../util/duration.js";

export interface AccessTokenPayload {
  sub: string;
  role: UserRole;
  type: "access";
}

export interface RefreshTokenPayload {
  sub: string;
  role: UserRole;
  type: "refresh";
  /** Identyfikator wersji sesji - pozwala uniewaznic refresh tokeny przy logout/zmianie hasla (przyszle rozszerzenie). */
  jti: string;
}

export function signAccessToken(payload: Omit<AccessTokenPayload, "type">, secret: string, ttl: string): string {
  return jwt.sign({ ...payload, type: "access" }, secret, { expiresIn: durationToSeconds(ttl) });
}

export function signRefreshToken(payload: Omit<RefreshTokenPayload, "type">, secret: string, ttl: string): string {
  return jwt.sign({ ...payload, type: "refresh" }, secret, { expiresIn: durationToSeconds(ttl) });
}

export function verifyAccessToken(token: string, secret: string): AccessTokenPayload {
  const decoded = jwt.verify(token, secret) as AccessTokenPayload;
  if (decoded.type !== "access") throw new Error("Nieprawidlowy typ tokenu");
  return decoded;
}

export function verifyRefreshToken(token: string, secret: string): RefreshTokenPayload {
  const decoded = jwt.verify(token, secret) as RefreshTokenPayload;
  if (decoded.type !== "refresh") throw new Error("Nieprawidlowy typ tokenu");
  return decoded;
}
