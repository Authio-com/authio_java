package com.authio;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Verifies inbound Authio webhook signatures.
 *
 * <p>Mirrors the platform signing primitive exactly (authio_webhooks
 * {@code internal/signing}). The {@code Authio-Signature} header is
 * Stripe-style:
 *
 * <pre>Authio-Signature: t=&lt;unix-seconds&gt;,v1=&lt;hex-hmac-sha256&gt;</pre>
 *
 * <p>The signature is HMAC-SHA256 over {@code <t>.<raw-body>} using the
 * per-endpoint {@code whsec_…} secret. Callers MUST verify against the
 * <em>raw</em> request body (pre-JSON-parse). A tolerance window (default
 * 5 minutes) defeats replay; pass {@code 0} to disable the time check.
 */
public final class WebhookSignature {
  /** Default replay tolerance: 5 minutes, matching the platform receivers. */
  public static final long DEFAULT_TOLERANCE_SECONDS = 300L;

  private WebhookSignature() {}

  /** Verify with the default 5-minute tolerance. */
  public static boolean verify(String secret, String body, String signatureHeader) {
    return verify(secret, body, signatureHeader, DEFAULT_TOLERANCE_SECONDS);
  }

  /**
   * Verify a signature header against a raw body.
   *
   * @param toleranceSeconds max age (and skew) allowed for {@code t}; {@code 0}
   *     disables the time check entirely
   * @return true iff the signature is present, well-formed, fresh, and valid
   */
  public static boolean verify(String secret, String body, String signatureHeader, long toleranceSeconds) {
    if (secret == null || body == null || signatureHeader == null) {
      return false;
    }
    String t = null;
    String v1 = null;
    for (String part : signatureHeader.split(",")) {
      if (part.startsWith("t=")) {
        t = part.substring(2);
      } else if (part.startsWith("v1=")) {
        v1 = part.substring(3);
      }
    }
    if (t == null || t.isEmpty() || v1 == null || v1.isEmpty()) {
      return false;
    }
    long ts;
    try {
      ts = Long.parseLong(t);
    } catch (NumberFormatException e) {
      return false;
    }
    if (toleranceSeconds > 0) {
      long age = (System.currentTimeMillis() / 1000L) - ts;
      if (age > toleranceSeconds || age < -toleranceSeconds) {
        return false;
      }
    }
    byte[] want = hmacSha256(secret, t + "." + body);
    byte[] got = decodeHex(v1);
    if (got == null) {
      return false;
    }
    return MessageDigest.isEqual(want, got);
  }

  /** Compute the {@code Authio-Signature} header value (useful for tests/replay). */
  public static String sign(String secret, String body, long unixSeconds) {
    String t = Long.toString(unixSeconds);
    return "t=" + t + ",v1=" + encodeHex(hmacSha256(secret, t + "." + body));
  }

  private static byte[] hmacSha256(String secret, String data) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new IllegalStateException("HmacSHA256 unavailable", e);
    }
  }

  private static final char[] HEX = "0123456789abcdef".toCharArray();

  private static String encodeHex(byte[] bytes) {
    char[] out = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      int v = bytes[i] & 0xff;
      out[i * 2] = HEX[v >>> 4];
      out[i * 2 + 1] = HEX[v & 0x0f];
    }
    return new String(out);
  }

  private static byte[] decodeHex(String s) {
    int len = s.length();
    if ((len & 1) != 0) {
      return null;
    }
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      int hi = Character.digit(s.charAt(i), 16);
      int lo = Character.digit(s.charAt(i + 1), 16);
      if (hi < 0 || lo < 0) {
        return null;
      }
      out[i / 2] = (byte) ((hi << 4) | lo);
    }
    return out;
  }
}
