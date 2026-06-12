package com.authio;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * Internal HTTP plumbing: bearer auth, the {@code X-Authio-SDK} header on every
 * request, typed error mapping, and automatic retry-with-backoff on 429/5xx.
 */
final class Transport {
  private final AuthioOptions opts;
  private final HttpClient http;

  Transport(AuthioOptions opts) {
    this.opts = opts;
    this.http =
        HttpClient.newBuilder()
            .connectTimeout(opts.connectTimeout)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
  }

  /** Authenticated JSON request against the management API ({@code apiUrl}). */
  <T> T request(String method, String path, Object body, JavaType type) {
    HttpRequest.Builder rb =
        baseRequest(opts.apiUrl + path)
            .header("Authorization", "Bearer " + opts.apiKey);
    byte[] payload = null;
    if (body != null) {
      payload = serialize(body);
      rb.header("Content-Type", "application/json");
    }
    rb.method(method, payload != null
        ? HttpRequest.BodyPublishers.ofByteArray(payload)
        : HttpRequest.BodyPublishers.noBody());
    return send(rb.build(), type);
  }

  /**
   * Unauthenticated {@code application/x-www-form-urlencoded} POST against
   * auth-core ({@code authCoreUrl}); used by the OAuth token endpoint.
   */
  <T> T postForm(String path, Map<String, String> form, JavaType type) {
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, String> e : form.entrySet()) {
      if (e.getValue() == null) {
        continue;
      }
      if (sb.length() > 0) {
        sb.append('&');
      }
      sb.append(urlEncode(e.getKey())).append('=').append(urlEncode(e.getValue()));
    }
    HttpRequest req =
        baseRequest(opts.authCoreUrl + path)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(sb.toString(), StandardCharsets.UTF_8))
            .build();
    return send(req, type);
  }

  private HttpRequest.Builder baseRequest(String url) {
    return HttpRequest.newBuilder()
        .uri(URI.create(url))
        .timeout(opts.requestTimeout)
        .header("Accept", "application/json")
        .header("User-Agent", Version.USER_AGENT)
        .header("X-Authio-SDK", Version.SDK_HEADER);
  }

  private <T> T send(HttpRequest req, JavaType type) {
    int attempt = 0;
    while (true) {
      HttpResponse<byte[]> res;
      try {
        res = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
      } catch (IOException ex) {
        if (attempt < opts.maxRetries) {
          backoff(attempt++);
          continue;
        }
        throw new AuthioError("network_error", ex.getMessage(), 0, null, ex);
      } catch (InterruptedException ex) {
        Thread.currentThread().interrupt();
        throw new AuthioError("interrupted", ex.getMessage(), 0, null, ex);
      }

      int status = res.statusCode();
      if (isRetryable(status) && attempt < opts.maxRetries) {
        backoff(attempt++);
        continue;
      }
      if (status >= 400) {
        throw toError(res);
      }
      return deserialize(res.body(), type);
    }
  }

  private static boolean isRetryable(int status) {
    return status == 429 || (status >= 500 && status <= 599);
  }

  private void backoff(int attempt) {
    long base = opts.retryBaseDelay.toMillis();
    long delay = base * (1L << attempt);
    long jitter = (long) (Math.random() * base);
    try {
      Thread.sleep(delay + jitter);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private AuthioError toError(HttpResponse<byte[]> res) {
    String code = "request_failed";
    String message = "Request failed with status " + res.statusCode();
    String requestId = null;
    try {
      JsonNode n = Json.MAPPER.readTree(res.body());
      if (n.hasNonNull("code")) {
        code = n.get("code").asText();
      } else if (n.hasNonNull("error")) {
        // RFC 6749 §5.2 envelope from the token endpoint.
        code = n.get("error").asText();
      }
      if (n.hasNonNull("message")) {
        message = n.get("message").asText();
      } else if (n.hasNonNull("error_description")) {
        message = n.get("error_description").asText();
      }
      if (n.hasNonNull("request_id")) {
        requestId = n.get("request_id").asText();
      }
    } catch (Exception ignore) {
      // Non-JSON body — keep the generic message.
    }
    return new AuthioError(code, message, res.statusCode(), requestId);
  }

  @SuppressWarnings("unchecked")
  private <T> T deserialize(byte[] body, JavaType type) {
    if (type == null || type.getRawClass() == Void.class) {
      return null;
    }
    if (body == null || body.length == 0) {
      return null;
    }
    try {
      return Json.MAPPER.readValue(body, type);
    } catch (IOException ex) {
      throw new AuthioError("deserialization_error", ex.getMessage(), 0, null, ex);
    }
  }

  private byte[] serialize(Object body) {
    try {
      return Json.MAPPER.writeValueAsBytes(body);
    } catch (IOException ex) {
      throw new AuthioError("serialization_error", ex.getMessage(), 0, null, ex);
    }
  }

  static JavaType typeOf(Class<?> clazz) {
    return Json.MAPPER.getTypeFactory().constructType(clazz);
  }

  static JavaType listOf(Class<?> element) {
    return Json.MAPPER.getTypeFactory().constructCollectionType(java.util.List.class, element);
  }

  private static String urlEncode(String s) {
    return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
  }

  /** Exposed for unused-field linters; the configured timeout is enforced per request. */
  Duration requestTimeout() {
    return opts.requestTimeout;
  }
}
