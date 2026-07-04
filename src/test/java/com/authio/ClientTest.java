package com.authio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.authio.MockServer.Recorded;
import com.authio.MockServer.Response;
import com.authio.models.ClientCredentialsInput;
import com.authio.models.CreateOrganizationInput;
import com.authio.models.GenerateLinkInput;
import com.authio.models.ListUsersOptions;
import com.authio.models.Organization;
import com.authio.models.PortalLink;
import com.authio.models.TokenResponse;
import com.authio.models.UserList;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ClientTest {

  private Authio client(MockServer s) {
    return Authio.builder("sk_test_abc")
        .apiUrl(s.baseUrl())
        .authCoreUrl(s.baseUrl())
        .maxRetries(2)
        .retryBaseDelay(Duration.ofMillis(1))
        .buildClient();
  }

  @Test
  void requiresApiKey() {
    assertThrows(IllegalArgumentException.class, () -> Authio.builder("").buildClient());
    assertThrows(IllegalArgumentException.class, () -> Authio.builder(null).buildClient());
  }

  @Test
  void sendsAuthAndSdkHeaders() throws Exception {
    try (MockServer s =
        new MockServer(MockServer.sequence(new Response(200, "{\"data\":[],\"next_cursor\":null}")))) {
      Authio a = client(s);
      a.users.list();
      Recorded r = s.requests.get(0);
      assertEquals("Bearer sk_test_abc", r.header("Authorization"));
      assertEquals("java/" + Version.SDK_VERSION, r.header("X-Authio-SDK"));
      assertTrue(r.header("User-Agent").startsWith("authio-java/"));
    }
  }

  @Test
  void usersListSerializesQueryAndParses() throws Exception {
    try (MockServer s =
        new MockServer(
            MockServer.sequence(
                new Response(
                    200,
                    "{\"data\":[{\"id\":\"user_1\",\"project_id\":\"proj_1\",\"email\":\"a@b.com\","
                        + "\"email_verified\":true}],\"next_cursor\":\"cur2\"}")))) {
      Authio a = client(s);
      UserList res = a.users.list(new ListUsersOptions().email("a@b.com").limit(50).cursor("cur1"));
      assertEquals(1, res.data.size());
      assertEquals("user_1", res.data.get(0).id);
      assertTrue(res.data.get(0).emailVerified);
      assertEquals("cur2", res.nextCursor);
      Recorded r = s.requests.get(0);
      assertEquals("/v1/users", r.path);
      assertTrue(r.query.contains("email=a%40b.com"));
      assertTrue(r.query.contains("limit=50"));
      assertTrue(r.query.contains("cursor=cur1"));
    }
  }

  @Test
  void mapsTypedError() throws Exception {
    try (MockServer s =
        new MockServer(
            MockServer.sequence(
                new Response(
                    404,
                    "{\"code\":\"organization_not_found\",\"message\":\"no such org\","
                        + "\"request_id\":\"req_42\"}")))) {
      Authio a = client(s);
      AuthioError err = assertThrows(AuthioError.class, () -> a.organizations.get("org_x"));
      assertEquals("organization_not_found", err.getCode());
      assertEquals(404, err.getStatus());
      assertEquals("req_42", err.getRequestId());
      assertEquals("no such org", err.getMessage());
    }
  }

  @Test
  void retriesOn429ThenSucceeds() throws Exception {
    AtomicInteger calls = new AtomicInteger();
    try (MockServer s =
        new MockServer(
            (Recorded req) -> {
              int n = calls.incrementAndGet();
              if (n < 3) {
                return new Response(429, "{\"code\":\"rate_limit_exceeded\"}");
              }
              return new Response(200, "[{\"id\":\"org_1\",\"project_id\":\"p\",\"name\":\"Acme\","
                  + "\"slug\":\"acme\",\"created_at\":\"2026-01-01T00:00:00Z\"}]");
            })) {
      Authio a = client(s);
      var orgs = a.organizations.list();
      assertEquals(1, orgs.size());
      assertEquals("Acme", orgs.get(0).name);
      assertEquals(3, calls.get());
    }
  }

  @Test
  void retriesExhaustedThrows() throws Exception {
    try (MockServer s =
        new MockServer(MockServer.sequence(new Response(503, "{\"code\":\"unavailable\"}")))) {
      Authio a = client(s);
      AuthioError err = assertThrows(AuthioError.class, () -> a.organizations.list());
      assertEquals(503, err.getStatus());
      // 1 initial + 2 retries = 3 attempts.
      assertEquals(3, s.requests.size());
    }
  }

  @Test
  void createOrganizationSendsJsonBody() throws Exception {
    try (MockServer s =
        new MockServer(
            MockServer.sequence(
                new Response(
                    201,
                    "{\"id\":\"org_9\",\"project_id\":\"p\",\"name\":\"Acme\",\"slug\":\"acme\","
                        + "\"created_at\":\"2026-01-01T00:00:00Z\"}")))) {
      Authio a = client(s);
      Organization org = a.organizations.create(new CreateOrganizationInput("Acme").slug("acme"));
      assertEquals("org_9", org.id);
      Recorded r = s.requests.get(0);
      assertEquals("POST", r.method);
      assertEquals("application/json", r.header("Content-Type"));
      assertTrue(r.body.contains("\"name\":\"Acme\""));
      assertTrue(r.body.contains("\"slug\":\"acme\""));
    }
  }

  @Test
  void tokenPostsFormUrlEncoded() throws Exception {
    try (MockServer s =
        new MockServer(
            MockServer.sequence(
                new Response(
                    200,
                    "{\"access_token\":\"jwt.value\",\"token_type\":\"Bearer\","
                        + "\"expires_in\":3600,\"scope\":\"users:read\"}")))) {
      Authio a = client(s);
      TokenResponse res =
          a.token(new ClientCredentialsInput("m2m_abc", "secret_xyz").scope("users:read"));
      assertEquals("jwt.value", res.accessToken);
      assertEquals("Bearer", res.tokenType);
      assertEquals(3600, res.expiresIn);
      Recorded r = s.requests.get(0);
      assertEquals("/v1/auth/token", r.path);
      assertEquals("application/x-www-form-urlencoded", r.header("Content-Type"));
      assertTrue(r.body.contains("grant_type=client_credentials"));
      assertTrue(r.body.contains("client_id=m2m_abc"));
      assertTrue(r.body.contains("client_secret=secret_xyz"));
      // The token endpoint is unauthenticated (no bearer key leaked).
      assertNull(r.header("Authorization"));
    }
  }

  @Test
  void tokenMapsRfc6749ErrorEnvelope() throws Exception {
    try (MockServer s =
        new MockServer(
            MockServer.sequence(
                new Response(
                    401,
                    "{\"error\":\"invalid_client\",\"error_description\":\"unknown client\"}")))) {
      Authio a = client(s);
      AuthioError err =
          assertThrows(
              AuthioError.class,
              () -> a.token(new ClientCredentialsInput("m2m_abc", "wrong")));
      assertEquals("invalid_client", err.getCode());
      assertEquals(401, err.getStatus());
      assertEquals("unknown client", err.getMessage());
    }
  }

  @Test
  void portalGenerateLink() throws Exception {
    try (MockServer s =
        new MockServer(
            MockServer.sequence(
                new Response(
                    201,
                    "{\"link\":\"https://portal.authio.com/setup/abc\","
                        + "\"expires_at\":\"2026-06-11T00:05:00Z\"}")))) {
      Authio a = client(s);
      PortalLink link =
          a.portal.generateLink(
              new GenerateLinkInput("org_1", GenerateLinkInput.Intent.SSO)
                  .successUrl("https://app.example.com/done"));
      assertNotNull(link.link);
      assertEquals("2026-06-11T00:05:00Z", link.expiresAt);
      Recorded r = s.requests.get(0);
      assertTrue(r.body.contains("\"organization_id\":\"org_1\""));
      assertTrue(r.body.contains("\"intent\":\"sso\""));
      assertTrue(r.body.contains("\"success_url\":\"https://app.example.com/done\""));
    }
  }
}
