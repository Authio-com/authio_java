package com.authio.models;

/** Result of {@code portal.generateLink} — a ready-to-redirect setup link. */
public class PortalLink {
  /** The ready-to-redirect setup-portal URL. */
  public String link;
  /** ISO-8601 expiry. */
  public String expiresAt;
}
