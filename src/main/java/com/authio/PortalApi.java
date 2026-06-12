package com.authio;

import com.authio.models.GenerateLinkInput;
import com.authio.models.PortalLink;

/** The {@code portal} namespace (Admin Portal link generation). */
public final class PortalApi {
  private final Transport t;

  PortalApi(Transport t) {
    this.t = t;
  }

  /**
   * Mint a one-time, organization-scoped SSO/SCIM/domain setup link
   * (WorkOS-parity {@code generate_link}).
   */
  public PortalLink generateLink(GenerateLinkInput input) {
    return t.request("POST", "/v1/portal/setup-links", input, Transport.typeOf(PortalLink.class));
  }
}
