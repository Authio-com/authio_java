package com.authio;

import com.authio.models.AddMembershipInput;
import com.authio.models.Membership;
import com.authio.models.UpdateMembershipInput;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** The {@code memberships} namespace (organization membership management). */
public final class MembershipsApi {
  private final Transport t;

  MembershipsApi(Transport t) {
    this.t = t;
  }

  /** List members of an organization (joined with user records). */
  public List<Membership.WithUser> listForOrganization(String orgId) {
    return t.request(
        "GET",
        "/v1/organizations/" + enc(orgId) + "/memberships",
        null,
        Transport.listOf(Membership.WithUser.class));
  }

  /** Add an existing user to an organization. */
  public Membership add(String orgId, AddMembershipInput input) {
    return t.request(
        "POST",
        "/v1/organizations/" + enc(orgId) + "/memberships",
        input,
        Transport.typeOf(Membership.class));
  }

  /** Update a membership's role and/or status. */
  public Membership update(String orgId, String membershipId, UpdateMembershipInput input) {
    return t.request(
        "PATCH",
        "/v1/organizations/" + enc(orgId) + "/memberships/" + enc(membershipId),
        input,
        Transport.typeOf(Membership.class));
  }

  /** Remove a user's membership in one organization. */
  public void remove(String orgId, String membershipId) {
    t.request(
        "DELETE",
        "/v1/organizations/" + enc(orgId) + "/memberships/" + enc(membershipId),
        null,
        Transport.typeOf(Void.class));
  }

  private static String enc(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8);
  }
}
