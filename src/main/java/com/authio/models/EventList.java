package com.authio.models;

import java.util.List;

/**
 * A page of events, WorkOS-shaped: {@code { data, list_metadata: { after } }}.
 * Follow {@code listMetadata.after} until it is {@code null} to drain the feed.
 */
public class EventList {
  public List<Event> data;
  public ListMetadata listMetadata;

  public static class ListMetadata {
    /** Cursor for the next page, or {@code null} when fully drained. */
    public String after;
  }
}
