package com.authio.models;

import java.util.ArrayList;
import java.util.List;

/** Filters for {@code events.list} / {@code events.iterate}. */
public final class ListEventsOptions {
  public List<String> events;
  public String rangeStart;
  public String rangeEnd;
  public Integer limit;
  public String after;

  public ListEventsOptions events(String... events) {
    this.events = new ArrayList<>(List.of(events));
    return this;
  }

  public ListEventsOptions rangeStart(String rangeStart) {
    this.rangeStart = rangeStart;
    return this;
  }

  public ListEventsOptions rangeEnd(String rangeEnd) {
    this.rangeEnd = rangeEnd;
    return this;
  }

  public ListEventsOptions limit(int limit) {
    this.limit = limit;
    return this;
  }

  public ListEventsOptions after(String after) {
    this.after = after;
    return this;
  }
}
