package com.authio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.authio.MockServer.Recorded;
import com.authio.MockServer.Response;
import com.authio.models.Event;
import com.authio.models.EventList;
import com.authio.models.ListEventsOptions;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class EventsIteratorTest {

  private Authio client(MockServer s) {
    return Authio.builder("sk_test").apiUrl(s.baseUrl()).authCoreUrl(s.baseUrl()).buildClient();
  }

  private static String page(String after, String... ids) {
    StringBuilder sb = new StringBuilder("{\"data\":[");
    for (int i = 0; i < ids.length; i++) {
      if (i > 0) sb.append(',');
      sb.append("{\"id\":\"").append(ids[i]).append("\",\"event\":\"user.created\",")
          .append("\"created_at\":\"2026-06-11T00:00:00Z\",\"data\":{\"actor_type\":\"user\"}}");
    }
    sb.append("],\"list_metadata\":{\"after\":");
    sb.append(after == null ? "null" : "\"" + after + "\"");
    sb.append("}}");
    return sb.toString();
  }

  @Test
  void listSerializesQueryAndMapsListMetadata() throws Exception {
    try (MockServer s = new MockServer(MockServer.sequence(new Response(200, page("cur1", "evt_1"))))) {
      Authio a = client(s);
      EventList res =
          a.events.list(
              new ListEventsOptions()
                  .events("user.created", "session.created")
                  .rangeStart("2026-06-01T00:00:00Z")
                  .limit(50)
                  .after("abc"));
      assertEquals(1, res.data.size());
      assertEquals("cur1", res.listMetadata.after);
      Recorded r = s.requests.get(0);
      assertEquals("/v1/events", r.path);
      assertTrue(r.query.contains("events%5B%5D=user.created"));
      assertTrue(r.query.contains("events%5B%5D=session.created"));
      assertTrue(r.query.contains("range_start="));
      assertTrue(r.query.contains("limit=50"));
      assertTrue(r.query.contains("after=abc"));
    }
  }

  @Test
  void iterateWalksEveryPageOnceUntilAfterNull() throws Exception {
    try (MockServer s =
        new MockServer(
            MockServer.sequence(
                new Response(200, page("c1", "evt_1", "evt_2")),
                new Response(200, page("c2", "evt_3", "evt_4")),
                new Response(200, page(null, "evt_5"))))) {
      Authio a = client(s);
      List<String> seen = new ArrayList<>();
      for (Event e : a.events.iterate(new ListEventsOptions().events("user.created"))) {
        seen.add(e.id);
      }
      assertEquals(List.of("evt_1", "evt_2", "evt_3", "evt_4", "evt_5"), seen);
      Set<String> unique = new LinkedHashSet<>(seen);
      assertEquals(5, unique.size());
      // First page carries no cursor; subsequent pages carry the prior after.
      assertNull(s.requests.get(0).query == null ? null : queryParam(s.requests.get(0).query, "after"));
      assertEquals("c1", queryParam(s.requests.get(1).query, "after"));
      assertEquals("c2", queryParam(s.requests.get(2).query, "after"));
    }
  }

  @Test
  void iterateStopsCleanlyOnEmptyFirstPage() throws Exception {
    try (MockServer s = new MockServer(MockServer.sequence(new Response(200, page(null))))) {
      Authio a = client(s);
      int count = 0;
      for (Event ignored : a.events.iterate()) {
        count++;
      }
      assertEquals(0, count);
      assertEquals(1, s.requests.size());
    }
  }

  private static String queryParam(String query, String key) {
    if (query == null) return null;
    for (String p : query.split("&")) {
      int eq = p.indexOf('=');
      if (eq > 0 && p.substring(0, eq).equals(key)) {
        return p.substring(eq + 1);
      }
    }
    return null;
  }
}
