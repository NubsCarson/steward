/**
 * SessionManager — JWT-based session creation and verification using jose.
 *
 * jose is a root-level dependency (package.json: "jose": "^6.2.1") so it is
 * available to all packages via the monorepo workspace.
 */

import { randomUUID } from "node:crypto";
import { type JWTPayload, jwtVerify, SignJWT } from "jose";
import { assertTokenNotRevoked, revocationStore, TokenRevokedError } from "./revocation.js";

// ─── Config ────────────────────────────────────────────────────────────────

export interface SessionConfig {
  /** JWT signing secret — at least 32 random bytes recommended */
  secret: string;
  /** JWT issuer claim. Defaults to "steward" */
  issuer?: string;
  /**
   * Token lifetime expressed as a relative time string understood by jose,
   * e.g. "7d", "24h", "30m". Defaults to "7d".
   */
  expiresIn?: string;
}

// ─── Payload ───────────────────────────────────────────────────────────────

export interface SessionPayload extends JWTPayload {
  userId: string;
  jti: string;
  [key: string]: unknown;
}

// ─── Class ─────────────────────────────────────────────────────────────────

export class SessionManager {
  private readonly secret: Uint8Array;
  private readonly issuer: string;
  private readonly expiresIn: string;

  constructor(config: SessionConfig) {
    if (!config.secret || config.secret.length < 16) {
      throw new Error(
        "SessionManager: secret must be at least 16 characters. Use a long random string in production.",
      );
    }
    this.secret = new TextEncoder().encode(config.secret);
    this.issuer = config.issuer ?? "steward";
    this.expiresIn = config.expiresIn ?? "7d";
  }

  /**
   * Create a signed JWT for a user session.
   *
   * @param userId  The user's UUID or identifier — included as a top-level claim
   * @param extra   Optional additional claims to embed in the token
   * @returns       A compact JWT string suitable for use as a session token
   */
  async createSession(userId: string, extra?: Record<string, unknown>): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    const builder = new SignJWT({
      userId,
      ...extra,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer(this.issuer)
      .setIssuedAt(now)
      .setJti(randomUUID())
      .setExpirationTime(this.expiresIn as Parameters<SignJWT["setExpirationTime"]>[0]);

    return builder.sign(this.secret);
  }

  /**
   * Verify and decode a session JWT.
   *
   * Returns the payload (including `userId`) on success, or `null` if the
   * token is invalid, expired, or has been tampered with.
   *
   * @param token  The compact JWT string
   */
  async verifySession(token: string): Promise<SessionPayload | null> {
    try {
      const { payload } = await jwtVerify(token, this.secret, {
        issuer: this.issuer,
        algorithms: ["HS256"],
      });

      // Sanity-check our custom claims are present
      if (typeof payload.userId !== "string" || typeof payload.jti !== "string") {
        return null;
      }

      await assertTokenNotRevoked(payload);

      return payload as SessionPayload;
    } catch (err) {
      if (err instanceof TokenRevokedError) throw err;
      // Covers JWTExpired, JWTInvalid, JWSInvalid, etc.
      return null;
    }
  }

  /**
   * Invalidate a session token by adding its JTI to the revocation store until
   * the token's natural expiry. Redis shares this across instances; without
   * REDIS_URL the store is in-memory for single-instance/embedded mode.
   *
   * @param token  The token to invalidate
   */
  async invalidateSession(token: string): Promise<void> {
    const { payload } = await jwtVerify(token, this.secret, {
      issuer: this.issuer,
      algorithms: ["HS256"],
    });

    if (typeof payload.jti !== "string" || typeof payload.exp !== "number") {
      throw new Error("Session token is missing revocable jti/exp claims");
    }

    await revocationStore.revokeToken(payload.jti, payload.exp);
  }
}
