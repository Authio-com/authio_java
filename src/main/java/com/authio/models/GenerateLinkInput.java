package com.authio.models;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.List;

/** Body for {@code portal.generateLink} (WorkOS-parity {@code generate_link}). */
public final class GenerateLinkInput {
  public String organizationId;
  public Intent intent;
  public String returnUrl;
  public String successUrl;
  public List<String> itContactEmails;
  public Integer expiresInMinutes;

  public GenerateLinkInput(String organizationId, Intent intent) {
    this.organizationId = organizationId;
    this.intent = intent;
  }

  public GenerateLinkInput returnUrl(String returnUrl) {
    this.returnUrl = returnUrl;
    return this;
  }

  public GenerateLinkInput successUrl(String successUrl) {
    this.successUrl = successUrl;
    return this;
  }

  public GenerateLinkInput itContactEmails(List<String> emails) {
    this.itContactEmails = emails;
    return this;
  }

  public GenerateLinkInput expiresInMinutes(int minutes) {
    this.expiresInMinutes = minutes;
    return this;
  }

  /** What the IT admin will configure via the portal. */
  public enum Intent {
    SSO("sso"),
    SCIM("scim"),
    DOMAIN("domain");

    private final String wire;

    Intent(String wire) {
      this.wire = wire;
    }

    @JsonValue
    public String wire() {
      return wire;
    }
  }
}
