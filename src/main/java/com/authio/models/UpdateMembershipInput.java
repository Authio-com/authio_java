package com.authio.models;

/** Body for {@code organizations.updateMember} (role and/or status). */
public final class UpdateMembershipInput {
  public String role;
  public MembershipStatus status;

  public UpdateMembershipInput role(String role) {
    this.role = role;
    return this;
  }

  public UpdateMembershipInput status(MembershipStatus status) {
    this.status = status;
    return this;
  }
}
