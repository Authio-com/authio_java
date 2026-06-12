package com.authio.models;

/** Body for {@code organizations.invite}. */
public final class CreateInvitationInput {
  public String email;
  public String role;
  public String redirectUri;

  public CreateInvitationInput(String email) {
    this.email = email;
  }

  public CreateInvitationInput role(String role) {
    this.role = role;
    return this;
  }

  public CreateInvitationInput redirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
    return this;
  }
}
