package com.authio.models;

import java.util.List;

/** A page of webhook deliveries plus a status rollup. */
public class WebhookDeliveriesPage {
  public List<WebhookDelivery> data;
  public String nextCursor;
  public Summary summary;

  public static class Summary {
    public int succeeded;
    public int failed;
    public int pending;
    public int dead;
  }
}
