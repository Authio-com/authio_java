package com.authio;

import com.authio.models.CreateInvitationInput;
import com.authio.models.Invitation;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/** The {@code invites} namespace. */
public final class InvitesApi {
  private final Transport t;

  InvitesApi(Transport t) {
    this.t = t;
  }

  /** Invite a user to an organization by email. */
  public Invitation create(String orgId, CreateInvitationInput input) {
    return t.request(
        "POST",
        "/v1/organizations/" + enc(orgId) + "/invitations",
        input,
        Transport.typeOf(Invitation.class));
  }

  private static String enc(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8);
  }
}
