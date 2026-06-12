package com.authio.models;

/** Ties a {@link User} to an {@link Organization} with a role. */
public class Membership {
  public String id;
  public String projectId;
  public String userId;
  public String organizationId;
  public String role;
  public MembershipStatus status;
  public String joinedAt;
  public String invitedBy;
  public String lastActiveAt;
  public String preferredLoginMethod;

  /** A membership row joined with its {@link Organization} (user-scoped reads). */
  public static class WithOrganization extends Membership {
    public Organization organization;
  }

  /** A membership row joined with its {@link User} (org-scoped reads). */
  public static class WithUser extends Membership {
    public User user;
  }
}
