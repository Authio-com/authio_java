package com.authio.models;

/** Body for {@code organizations.addMember}. */
public final class AddMembershipInput {
  public String userId;
  public String role;

  public AddMembershipInput(String userId, String role) {
    this.userId = userId;
    this.role = role;
  }
}
