package com.authio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.authio.MockServer.Response;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * End-to-end verification test. We mint a real Ed25519 keypair, serve a JWKS,
 * hand-sign a compact JWT with the JDK (no Tink needed), and assert the
 * verifier accepts valid tokens and rejects tampered/expired ones.
 */
class JwtVerifierTest {

  private static String b64(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  private static String b64(String s) {
    return b64(s.getBytes(StandardCharsets.UTF_8));
  }

  /** Sign a {header}.{payload} compact JWT with EdDSA via the JDK. */
  private static String signJwt(PrivateKey key, String kid, String claimsJson) throws Exception {
    String header = b64("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}");
    String payload = b64(claimsJson);
    String signingInput = header + "." + payload;
    Signature sig = Signature.getInstance("Ed25519");
    sig.initSign(key);
    sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
    return signingInput + "." + b64(sig.sign());
  }

  private static String jwks(KeyPair kp, String kid) {
    byte[] spki = kp.getPublic().getEncoded();
    byte[] raw = Arrays.copyOfRange(spki, spki.length - 32, spki.length);
    return "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"use\":\"sig\",\"alg\":\"EdDSA\","
        + "\"kid\":\"" + kid + "\",\"x\":\"" + b64(raw) + "\"}]}";
  }

  @Test
  void verifiesValidTokenAndBuildsSession() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String kid = "key-1";
    String jwksDoc = jwks(kp, kid);

    try (MockServer s = new MockServer(MockServer.sequence(new Response(200, jwksDoc)))) {
      Authio a = Authio.builder("sk_test").apiUrl(s.baseUrl()).authCoreUrl(s.baseUrl()).buildClient();
      long exp = (System.currentTimeMillis() / 1000L) + 3600;
      String claims =
          "{\"sub\":\"user_1\",\"sid\":\"sess_1\",\"act_org\":\"org_1\",\"act_role\":\"admin\","
              + "\"iss\":\"" + AuthioOptions.DEFAULT_ISSUER + "\",\"aud\":\""
              + AuthioOptions.DEFAULT_AUDIENCE + "\","
              + "\"exp\":" + exp + ",\"plan\":\"pro\"}";
      String token = signJwt(kp.getPrivate(), kid, claims);

      Session session = a.sessions.verify(token);
      assertNotNull(session);
      assertEquals("user_1", session.userId);
      assertEquals("sess_1", session.sessionId);
      assertEquals("org_1", session.orgId);
      assertEquals("admin", session.role);
      // Custom claim is surfaced; reserved claims are filtered out.
      assertEquals("pro", session.claims.get("plan"));
      assertNull(session.claims.get("sub"));
    }
  }

  @Test
  void returnsNullForTamperedToken() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String kid = "key-1";
    try (MockServer s = new MockServer(MockServer.sequence(new Response(200, jwks(kp, kid))))) {
      Authio a = Authio.builder("sk_test").apiUrl(s.baseUrl()).authCoreUrl(s.baseUrl()).buildClient();
      long exp = (System.currentTimeMillis() / 1000L) + 3600;
      String token = signJwt(kp.getPrivate(), kid, defaultClaims(exp));
      String tampered = token.substring(0, token.length() - 4) + "AAAA";
      assertNull(a.sessions.verify(tampered));
    }
  }

  @Test
  void rejectsExpiredToken() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String kid = "key-1";
    try (MockServer s = new MockServer(MockServer.sequence(new Response(200, jwks(kp, kid))))) {
      Authio a = Authio.builder("sk_test").apiUrl(s.baseUrl()).authCoreUrl(s.baseUrl()).buildClient();
      long exp = (System.currentTimeMillis() / 1000L) - 3600;
      String token = signJwt(kp.getPrivate(), kid, defaultClaims(exp));
      assertNull(a.sessions.verify(token));
      // The throwing variant surfaces the typed error.
      AuthioError err = assertThrows(AuthioError.class, () -> a.sessions.verifyOrThrow(token));
      assertEquals("invalid_token", err.getCode());
    }
  }

  @Test
  void enforcesIssuerAndAudienceWhenConfigured() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String kid = "key-1";
    try (MockServer s = new MockServer(MockServer.sequence(new Response(200, jwks(kp, kid))))) {
      Authio a =
          Authio.builder("sk_test")
              .apiUrl(s.baseUrl())
              .authCoreUrl(s.baseUrl())
              .jwtIssuer("https://api.authio.com")
              .jwtAudience("authio")
              .buildClient();
      long exp = (System.currentTimeMillis() / 1000L) + 3600;
      String wrongIss =
          signJwt(
              kp.getPrivate(),
              kid,
              "{\"sub\":\"u\",\"exp\":" + exp + ",\"iss\":\"https://evil.example\",\"aud\":\"authio\"}");
      assertNull(a.sessions.verify(wrongIss));
      String ok =
          signJwt(
              kp.getPrivate(),
              kid,
              "{\"sub\":\"u\",\"exp\":" + exp + ",\"iss\":\"https://api.authio.com\",\"aud\":\"authio\"}");
      assertNotNull(a.sessions.verify(ok));
    }
  }

  /** Claims carrying the issuer/audience auth-core really stamps. */
  private static String defaultClaims(long exp) {
    return "{\"sub\":\"user_1\",\"iss\":\"" + AuthioOptions.DEFAULT_ISSUER
        + "\",\"aud\":\"" + AuthioOptions.DEFAULT_AUDIENCE + "\",\"exp\":" + exp + "}";
  }

  // -------------------------------------------------------------------
  // Security audit 2026-09-18. issuer/audience defaulted to null, and a
  // null expected value means the check is skipped — so this SDK used to
  // verify the signature and nothing else. Every tenant shares one
  // signing key, so that accepted tokens from the whole platform.
  // -------------------------------------------------------------------

  @Test
  void enforcesIssuerAndAudienceByDefault() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String kid = "key-1";
    try (MockServer s = new MockServer(MockServer.sequence(new Response(200, jwks(kp, kid))))) {
      Authio a = Authio.builder("sk_test").apiUrl(s.baseUrl()).authCoreUrl(s.baseUrl()).buildClient();
      long exp = (System.currentTimeMillis() / 1000L) + 3600;
      String noIssNoAud =
          signJwt(kp.getPrivate(), kid, "{\"sub\":\"u\",\"exp\":" + exp + "}");
      assertNull(a.sessions.verify(noIssNoAud));
    }
  }

  @Test
  void rejectsTokenWithNoExpClaim() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String kid = "key-1";
    try (MockServer s = new MockServer(MockServer.sequence(new Response(200, jwks(kp, kid))))) {
      Authio a = Authio.builder("sk_test").apiUrl(s.baseUrl()).authCoreUrl(s.baseUrl()).buildClient();
      String noExp =
          signJwt(
              kp.getPrivate(),
              kid,
              "{\"sub\":\"u\",\"iss\":\"" + AuthioOptions.DEFAULT_ISSUER
                  + "\",\"aud\":\"" + AuthioOptions.DEFAULT_AUDIENCE + "\"}");
      assertNull(a.sessions.verify(noExp));
    }
  }

  @Test
  void rejectsTokenMintedInAnotherProject() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String kid = "key-1";
    try (MockServer s = new MockServer(MockServer.sequence(new Response(200, jwks(kp, kid))))) {
      Authio a =
          Authio.builder("sk_test")
              .apiUrl(s.baseUrl())
              .authCoreUrl(s.baseUrl())
              .projectId("proj_victim")
              .buildClient();
      long exp = (System.currentTimeMillis() / 1000L) + 3600;
      String foreign =
          signJwt(
              kp.getPrivate(),
              kid,
              "{\"sub\":\"u\",\"iss\":\"" + AuthioOptions.DEFAULT_ISSUER
                  + "\",\"aud\":\"" + AuthioOptions.DEFAULT_AUDIENCE
                  + "\",\"exp\":" + exp + ",\"project_id\":\"proj_attacker\"}");
      assertNull(a.sessions.verify(foreign));
    }
  }

  @Test
  void acceptsTokenMintedForTheConfiguredProject() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String kid = "key-1";
    try (MockServer s = new MockServer(MockServer.sequence(new Response(200, jwks(kp, kid))))) {
      Authio a =
          Authio.builder("sk_test")
              .apiUrl(s.baseUrl())
              .authCoreUrl(s.baseUrl())
              .projectId("proj_victim")
              .buildClient();
      long exp = (System.currentTimeMillis() / 1000L) + 3600;
      String ours =
          signJwt(
              kp.getPrivate(),
              kid,
              "{\"sub\":\"u\",\"iss\":\"" + AuthioOptions.DEFAULT_ISSUER
                  + "\",\"aud\":\"" + AuthioOptions.DEFAULT_AUDIENCE
                  + "\",\"exp\":" + exp + ",\"project_id\":\"proj_victim\"}");
      assertNotNull(a.sessions.verify(ours));
    }
  }

  @Test
  void rejectsTokenWithNoProjectIdWhenTenantConfigured() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String kid = "key-1";
    try (MockServer s = new MockServer(MockServer.sequence(new Response(200, jwks(kp, kid))))) {
      Authio a =
          Authio.builder("sk_test")
              .apiUrl(s.baseUrl())
              .authCoreUrl(s.baseUrl())
              .projectId("proj_victim")
              .buildClient();
      long exp = (System.currentTimeMillis() / 1000L) + 3600;
      assertNull(a.sessions.verify(signJwt(kp.getPrivate(), kid, defaultClaims(exp))));
    }
  }
}
