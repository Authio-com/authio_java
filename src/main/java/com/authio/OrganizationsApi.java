package com.authio;

import com.authio.models.CreateOrganizationInput;
import com.authio.models.Organization;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** The {@code organizations} namespace. */
public final class OrganizationsApi {
  private final Transport t;

  OrganizationsApi(Transport t) {
    this.t = t;
  }

  /** List all organizations in the project. */
  public List<Organization> list() {
    return t.request("GET", "/v1/organizations", null, Transport.listOf(Organization.class));
  }

  /** Create an organization. */
  public Organization create(CreateOrganizationInput input) {
    return t.request("POST", "/v1/organizations", input, Transport.typeOf(Organization.class));
  }

  /** Fetch a single organization by id. */
  public Organization get(String orgId) {
    return t.request(
        "GET", "/v1/organizations/" + enc(orgId), null, Transport.typeOf(Organization.class));
  }

  private static String enc(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8);
  }
}
