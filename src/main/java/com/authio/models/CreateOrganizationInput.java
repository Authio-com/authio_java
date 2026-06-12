package com.authio.models;

/** Body for {@code organizations.create}. */
public final class CreateOrganizationInput {
  public String name;
  public String slug;
  public String domain;

  public CreateOrganizationInput(String name) {
    this.name = name;
  }

  public CreateOrganizationInput slug(String slug) {
    this.slug = slug;
    return this;
  }

  public CreateOrganizationInput domain(String domain) {
    this.domain = domain;
    return this;
  }
}
