package com.authio;

import com.authio.models.ListUsersOptions;
import com.authio.models.Membership;
import com.authio.models.User;
import com.authio.models.UserList;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** The {@code users} namespace. */
public final class UsersApi {
  private final Transport t;

  UsersApi(Transport t) {
    this.t = t;
  }

  /** List users in the project. Supports {@code email}, {@code limit}, {@code cursor}. */
  public UserList list(ListUsersOptions opts) {
    StringBuilder q = new StringBuilder();
    if (opts != null) {
      if (opts.email != null) {
        append(q, "email", opts.email);
      }
      if (opts.limit != null) {
        append(q, "limit", String.valueOf(opts.limit));
      }
      if (opts.cursor != null) {
        append(q, "cursor", opts.cursor);
      }
    }
    String path = "/v1/users" + (q.length() > 0 ? "?" + q : "");
    return t.request("GET", path, null, Transport.typeOf(UserList.class));
  }

  /** List the first page of users with default options. */
  public UserList list() {
    return list(null);
  }

  /** Fetch a single user by id. */
  public User get(String userId) {
    return t.request("GET", "/v1/users/" + enc(userId), null, Transport.typeOf(User.class));
  }

  /** List every org membership for a user (project-scoped). */
  public List<Membership.WithOrganization> listMemberships(String userId) {
    return t.request(
        "GET",
        "/v1/users/" + enc(userId) + "/memberships",
        null,
        Transport.listOf(Membership.WithOrganization.class));
  }

  private static void append(StringBuilder q, String k, String v) {
    if (q.length() > 0) {
      q.append('&');
    }
    q.append(k).append('=').append(enc(v));
  }

  private static String enc(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8);
  }
}
