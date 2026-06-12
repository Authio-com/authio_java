package com.authio.models;

import java.util.Map;

/** A single audit event. Mirrors the wire {@code Event} schema. */
public class Event {
  public String id;
  public String event;
  public String createdAt;
  public Data data;

  /** The event payload (org/user/target ids + custom metadata). */
  public static class Data {
    public String organizationId;
    public String userId;
    public String actorType;
    public String actorId;
    public String targetType;
    public String targetId;
    public Map<String, Object> metadata;
  }
}
