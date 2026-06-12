package com.authio;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class WebhookSignatureTest {

  @Test
  void roundTripsWithDefaultTolerance() {
    long now = System.currentTimeMillis() / 1000L;
    String sig = WebhookSignature.sign("whsec_test", "hello", now);
    assertTrue(WebhookSignature.verify("whsec_test", "hello", sig));
  }

  @Test
  void rejectsTamperedBody() {
    long now = System.currentTimeMillis() / 1000L;
    String sig = WebhookSignature.sign("whsec_test", "hello", now);
    assertFalse(WebhookSignature.verify("whsec_test", "tampered", sig));
  }

  @Test
  void rejectsWrongSecret() {
    long now = System.currentTimeMillis() / 1000L;
    String sig = WebhookSignature.sign("whsec_test", "hello", now);
    assertFalse(WebhookSignature.verify("whsec_other", "hello", sig));
  }

  @Test
  void rejectsReplayOutsideTolerance() {
    long old = (System.currentTimeMillis() / 1000L) - 600;
    String sig = WebhookSignature.sign("whsec_test", "hello", old);
    assertFalse(WebhookSignature.verify("whsec_test", "hello", sig, 300));
    // With the time check disabled the same signature still validates.
    assertTrue(WebhookSignature.verify("whsec_test", "hello", sig, 0));
  }

  @Test
  void rejectsMalformedHeader() {
    assertFalse(WebhookSignature.verify("whsec_test", "hello", "garbage"));
    assertFalse(WebhookSignature.verify("whsec_test", "hello", "t=,v1="));
    assertFalse(WebhookSignature.verify("whsec_test", "hello", null));
  }

  @Test
  void matchesPlatformVectorFixedTimestamp() {
    // Mirrors authio_webhooks signing.SelfTest (t=1700000000, body="hello").
    String sig = WebhookSignature.sign("whsec_test", "hello", 1700000000L);
    assertTrue(sig.startsWith("t=1700000000,v1="));
    assertTrue(WebhookSignature.verify("whsec_test", "hello", sig, 0));
  }
}
