package com.authio.models;

/** A user identity. Mirrors the wire {@code User} schema. */
public class User {
  public String id;
  public String projectId;
  public String email;
  public boolean emailVerified;
  public String name;
  public String avatarUrl;
  public String defaultOrganizationId;
  public String createdAt;
  public String updatedAt;
}
