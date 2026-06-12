package com.authio;

import java.util.Map;

/**
 * A verified Authio session, decoded from an access-token JWT.
 *
 * <p>The session always identifies the <em>user</em> ({@link #userId}); the
 * active organization ({@link #orgId}) is only set after the user has selected
 * one of their memberships.
 */
public final class Session {
  public final String sessionId;
  public final String userId;
  public final String orgId;
  public final String role;
  public final String expiresAt;
  /** Custom (T2.4) claims merged into the token, minus reserved claim names. */
  public final Map<String, Object> claims;
  /** True when the session was minted by an Authio operator impersonating the user. */
  public final boolean impersonation;
  /** Admin email when {@link #impersonation} is true; otherwise null. */
  public final String impersonatorEmail;

  Session(
      String sessionId,
      String userId,
      String orgId,
      String role,
      String expiresAt,
      Map<String, Object> claims,
      boolean impersonation,
      String impersonatorEmail) {
    this.sessionId = sessionId;
    this.userId = userId;
    this.orgId = orgId;
    this.role = role;
    this.expiresAt = expiresAt;
    this.claims = claims;
    this.impersonation = impersonation;
    this.impersonatorEmail = impersonatorEmail;
  }
}
