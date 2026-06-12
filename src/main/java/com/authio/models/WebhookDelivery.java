package com.authio.models;

/** A single webhook delivery attempt record. */
public class WebhookDelivery {
  public String id;
  public String webhookId;
  public String eventId;
  public String eventType;
  public String status;
  public int attemptCount;
  public String lastAttemptAt;
  public Integer responseStatus;
  public boolean isTest;
  public String createdAt;
}
