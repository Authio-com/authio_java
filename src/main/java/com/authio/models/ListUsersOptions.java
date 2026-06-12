package com.authio.models;

/**
 * Filters for {@code users.list}. Per the OpenAPI contract the supported
 * params are {@code email}, {@code limit} (max 200, default 50) and
 * {@code cursor}. (Free-text {@code q}/{@code sort} are not part of the
 * public API contract for this endpoint.)
 */
public final class ListUsersOptions {
  public String email;
  public Integer limit;
  public String cursor;

  public ListUsersOptions email(String email) {
    this.email = email;
    return this;
  }

  public ListUsersOptions limit(int limit) {
    this.limit = limit;
    return this;
  }

  public ListUsersOptions cursor(String cursor) {
    this.cursor = cursor;
    return this;
  }
}
