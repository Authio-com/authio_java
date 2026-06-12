package com.authio.models;

/** An organization invitation. Mirrors the wire {@code Invitation} schema. */
public class Invitation {
  public String id;
  public String organizationId;
  public String email;
  public String role;
  public String status;
  public String expiresAt;
  public String createdAt;
}
