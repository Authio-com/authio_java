package com.authio.models;

import java.util.List;

/**
 * A page of users. Note: the users list uses {@code next_cursor} pagination
 * (distinct from the Events API's WorkOS-shaped {@code list_metadata.after}).
 */
public class UserList {
  public List<User> data;
  public String nextCursor;
}
