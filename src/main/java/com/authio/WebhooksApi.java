package com.authio;

import com.authio.models.WebhookDeliveriesPage;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * The {@code webhooks} namespace.
 *
 * <p>For verifying inbound webhook payloads, see {@link WebhookSignature}.
 */
public final class WebhooksApi {
  private final Transport t;

  WebhooksApi(Transport t) {
    this.t = t;
  }

  /** List delivery attempts for a webhook endpoint (cursor-paginated). */
  public WebhookDeliveriesPage listDeliveries(String webhookId, String cursor) {
    String path = "/v1/webhooks/" + enc(webhookId) + "/deliveries";
    if (cursor != null) {
      path += "?cursor=" + enc(cursor);
    }
    return t.request("GET", path, null, Transport.typeOf(WebhookDeliveriesPage.class));
  }

  /** List the first page of delivery attempts for a webhook endpoint. */
  public WebhookDeliveriesPage listDeliveries(String webhookId) {
    return listDeliveries(webhookId, null);
  }

  private static String enc(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8);
  }
}
