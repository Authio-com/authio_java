package com.authio.models;

import java.util.List;
import java.util.Map;

/** An organization. Mirrors the wire {@code Organization} schema. */
public class Organization {
  public String id;
  public String projectId;
  public String name;
  public String slug;
  public List<Domain> domains;
  public Map<String, Object> branding;
  public String createdAt;

  /** A verified email domain routed to this org for SSO/JIT. */
  public static class Domain {
    public String domain;
    public boolean verified;
    public String autoJoinRole;
  }
}
