package com.authio;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/** The {@code sessions} namespace — verify access-token JWTs. */
public final class SessionsApi {
  // Standard JWT + Authio reserved claim names — never copied into Session.claims.
  private static final Set<String> RESERVED =
      Set.of(
          "iss", "sub", "aud", "exp", "iat", "jti", "nbf", "scope", "scopes", "sid",
          "act_org", "act_role", "client_id", "token_type", "project_id", "kind",
          "is_impersonation", "impersonator_user_id", "impersonator_email", "imp_grant_id");

  private final JwtVerifier verifier;

  SessionsApi(JwtVerifier verifier) {
    this.verifier = verifier;
  }

  /**
   * Verify an access token and return the typed {@link Session}, or
   * {@code null} when the token is invalid or expired.
   */
  public Session verify(String accessToken) {
    if (accessToken == null || accessToken.isEmpty()) {
      return null;
    }
    try {
      return verifyOrThrow(accessToken);
    } catch (AuthioError e) {
      return null;
    }
  }

  /** Like {@link #verify}, but throws {@link AuthioError} on failure. */
  public Session verifyOrThrow(String accessToken) {
    Map<String, Object> claims = verifier.verify(accessToken);

    Map<String, Object> merged = new HashMap<>();
    for (Map.Entry<String, Object> e : claims.entrySet()) {
      if (!RESERVED.contains(e.getKey())) {
        merged.put(e.getKey(), e.getValue());
      }
    }

    String expiresAt;
    Object exp = claims.get("exp");
    if (exp instanceof Number n) {
      expiresAt = Instant.ofEpochSecond(n.longValue()).toString();
    } else {
      expiresAt = Instant.now().toString();
    }

    String actOrg = str(claims.get("act_org"));
    String actRole = str(claims.get("act_role"));
    boolean impersonation = Boolean.TRUE.equals(claims.get("is_impersonation"));

    return new Session(
        orEmpty(str(claims.get("sid"))),
        str(claims.get("sub")),
        (actOrg != null && !actOrg.isEmpty()) ? actOrg : null,
        (actRole != null && !actRole.isEmpty()) ? actRole : null,
        expiresAt,
        merged,
        impersonation,
        impersonation ? str(claims.get("impersonator_email")) : null);
  }

  private static String str(Object o) {
    return o == null ? null : String.valueOf(o);
  }

  private static String orEmpty(String s) {
    return s == null ? "" : s;
  }
}
