package com.authio;

import com.authio.models.Event;
import com.authio.models.EventList;
import com.authio.models.ListEventsOptions;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * The {@code events} namespace — cursor-paginated, project-scoped read over
 * audit events. WorkOS-shaped envelope ({@code { data, list_metadata.after }}).
 */
public final class EventsApi {
  private final Transport t;

  EventsApi(Transport t) {
    this.t = t;
  }

  /** Fetch a single page of events. */
  public EventList list(ListEventsOptions opts) {
    String path = "/v1/events" + query(opts);
    return t.request("GET", path, null, Transport.typeOf(EventList.class));
  }

  /** Fetch the most recent page with default options. */
  public EventList list() {
    return list(null);
  }

  /**
   * Auto-paginating iterable. Walks {@code after} cursors until the API returns
   * no more rows, yielding each event exactly once. Keyset pagination on
   * {@code (created_at, id)} guarantees no gaps and no duplicates.
   */
  public Iterable<Event> iterate(ListEventsOptions opts) {
    final ListEventsOptions base = opts != null ? opts : new ListEventsOptions();
    return () -> new Iterator<>() {
      private String after = base.after;
      private boolean started = false;
      private boolean done = false;
      private List<Event> page = List.of();
      private int idx = 0;

      private void fetchNext() {
        ListEventsOptions next = new ListEventsOptions();
        next.events = base.events;
        next.rangeStart = base.rangeStart;
        next.rangeEnd = base.rangeEnd;
        next.limit = base.limit != null ? base.limit : 100;
        next.after = after;
        EventList res = list(next);
        page = res.data != null ? res.data : List.of();
        idx = 0;
        after = res.listMetadata != null ? res.listMetadata.after : null;
        if (after == null || page.isEmpty()) {
          done = true;
        }
      }

      @Override
      public boolean hasNext() {
        if (!started) {
          started = true;
          fetchNext();
        }
        while (idx >= page.size() && !done) {
          fetchNext();
        }
        return idx < page.size();
      }

      @Override
      public Event next() {
        if (!hasNext()) {
          throw new NoSuchElementException();
        }
        return page.get(idx++);
      }
    };
  }

  /** Auto-paginating iterable over all events with default options. */
  public Iterable<Event> iterate() {
    return iterate(null);
  }

  private static String query(ListEventsOptions o) {
    if (o == null) {
      return "";
    }
    StringBuilder q = new StringBuilder();
    if (o.events != null) {
      for (String e : o.events) {
        append(q, "events[]", e);
      }
    }
    if (o.rangeStart != null) {
      append(q, "range_start", o.rangeStart);
    }
    if (o.rangeEnd != null) {
      append(q, "range_end", o.rangeEnd);
    }
    if (o.limit != null) {
      append(q, "limit", String.valueOf(o.limit));
    }
    if (o.after != null) {
      append(q, "after", o.after);
    }
    return q.length() > 0 ? "?" + q : "";
  }

  private static void append(StringBuilder q, String k, String v) {
    if (q.length() > 0) {
      q.append('&');
    }
    q.append(URLEncoder.encode(k, StandardCharsets.UTF_8))
        .append('=')
        .append(URLEncoder.encode(v, StandardCharsets.UTF_8));
  }
}
