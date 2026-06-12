# authio-java

> Part of **[Authio Lobby](https://authio.com/products/lobby)** —
> Authio's drop-in passwordless authentication. Learn more at
> https://authio.com/products/lobby.

Official server-side **Java** SDK for Authio. Use it from any Java 17+ backend
(Spring Boot, Quarkus, Micronaut, Javalin, plain `HttpServer`, ...) to verify
session JWTs, manage users, organizations, memberships, invitations, read the
events feed, generate Admin Portal links, mint M2M tokens, and verify inbound
webhook signatures.

Hand-written and contract-driven: every type and route mirrors the Authio
OpenAPI source of truth in
[`authio_proto`](https://github.com/Authio-com/authio_proto). No generated
blob, no heavyweight framework — just the JDK's built-in `HttpClient`, Jackson
for JSON, and Nimbus JOSE for JWT parsing (EdDSA crypto uses the JDK 17 native
`Ed25519` primitive, so no Tink/BouncyCastle dependency).

## Install

Java 17+ required.

```xml
<dependency>
  <groupId>com.authio</groupId>
  <artifactId>authio-java</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle:

```kotlin
implementation("com.authio:authio-java:0.1.0")
```

## Quick start

Verify a session JWT, list users, and generate a portal link:

```java
import com.authio.Authio;
import com.authio.Session;
import com.authio.models.GenerateLinkInput;
import com.authio.models.PortalLink;
import com.authio.models.UserList;

Authio authio = Authio.builder(System.getenv("AUTHIO_SECRET_KEY")).buildClient();

// 1. Verify a session access token (EdDSA JWT, verified against the JWKS).
//    Returns null when the token is invalid or expired.
Session session = authio.sessions.verify(accessToken);
if (session == null) {
  // 401 Unauthorized
  return;
}
// session.userId is always set; session.orgId only once the user picked an org.
System.out.println("user=" + session.userId + " org=" + session.orgId);

// 2. List users in the project.
UserList users = authio.users.list();
for (var u : users.data) {
  System.out.println(u.email);
}

// 3. Mint a one-time Admin Portal setup link and redirect your IT admin to it.
PortalLink link = authio.portal.generateLink(
    new GenerateLinkInput("org_123", GenerateLinkInput.Intent.SSO)
        .successUrl("https://app.example.com/settings/sso?done=1"));
// res.sendRedirect(link.link);
```

### Configuration

```java
import java.time.Duration;

Authio authio = Authio.builder("sk_live_...")
    .apiUrl("https://api.authio.com")        // management API base (default)
    .authCoreUrl("https://api.authio.com")   // token + JWKS origin (defaults to apiUrl)
    .jwtIssuer("https://api.authio.com")      // optional: enforce iss on verify
    .jwtAudience("authio")                     // optional: enforce aud on verify
    .requestTimeout(Duration.ofSeconds(30))
    .maxRetries(3)                             // retries 429/5xx with exp. backoff
    .buildClient();
```

The `Authorization: Bearer <apiKey>` and `X-Authio-SDK: java/<version>` headers
are sent on every management request. Requests automatically retry on `429`
and `5xx` with exponential backoff + jitter.

### Auto-paginating events iterator

The Events API is WorkOS-shaped (`{ data, list_metadata.after }`). Iterate the
whole feed with no gaps or duplicates — cursoring is handled for you:

```java
import com.authio.models.ListEventsOptions;

for (var event : authio.events.iterate(new ListEventsOptions().events("user.created"))) {
  System.out.println(event.id + " " + event.event + " " + event.createdAt);
}
```

### M2M (client credentials) token

```java
import com.authio.models.ClientCredentialsInput;
import com.authio.models.TokenResponse;

TokenResponse t = authio.token(
    new ClientCredentialsInput("m2m_...", "secret_...").scope("users:read"));
// t.accessToken is a Bearer JWT; verify it with authio.verifier().
```

### Verify an inbound webhook

Authio signs outbound webhooks with `Authio-Signature: t=<unix>,v1=<hmac-sha256>`
over `<t>.<raw-body>` using the endpoint's `whsec_…` secret. Verify against the
**raw** request body (5-minute replay tolerance by default):

```java
import com.authio.WebhookSignature;

boolean ok = WebhookSignature.verify(
    System.getenv("AUTHIO_WEBHOOK_SECRET"),  // whsec_...
    rawRequestBody,
    request.getHeader("Authio-Signature"));
if (!ok) {
  // 400 Bad Request — reject
}
```

### Typed errors

Every non-2xx API response throws `AuthioError` carrying the wire shape
(`code`, `message`, `request_id`) plus the HTTP `status`. Transport/network
failures surface as `AuthioError` with `status == 0`.

```java
try {
  authio.organizations.get("org_missing");
} catch (AuthioError e) {
  System.out.println(e.getCode() + " / " + e.getStatus() + " / " + e.getRequestId());
}
```

## Namespaces

| Namespace | Method | Wire endpoint |
|---|---|---|
| `sessions` | `verify(token)` / `verifyOrThrow(token)` | JWKS + EdDSA verify |
| `users` | `list(opts)` | `GET /v1/users` |
| `users` | `get(id)` | `GET /v1/users/{id}` |
| `users` | `listMemberships(id)` | `GET /v1/users/{id}/memberships` |
| `organizations` | `list()` | `GET /v1/organizations` |
| `organizations` | `create(input)` | `POST /v1/organizations` |
| `organizations` | `get(id)` | `GET /v1/organizations/{id}` |
| `memberships` | `listForOrganization(orgId)` | `GET /v1/organizations/{id}/memberships` |
| `memberships` | `add(orgId, input)` | `POST /v1/organizations/{id}/memberships` |
| `memberships` | `update(orgId, memId, input)` | `PATCH /v1/organizations/{id}/memberships/{memId}` |
| `memberships` | `remove(orgId, memId)` | `DELETE /v1/organizations/{id}/memberships/{memId}` |
| `invites` | `create(orgId, input)` | `POST /v1/organizations/{id}/invitations` |
| `events` | `list(opts)` / `iterate(opts)` | `GET /v1/events` |
| `portal` | `generateLink(input)` | `POST /v1/portal/setup-links` |
| `webhooks` | `listDeliveries(id, cursor)` | `GET /v1/webhooks/{id}/deliveries` |
| `token(input)` | M2M client credentials | `POST /v1/auth/token` |
| `WebhookSignature` | `verify(...)` / `sign(...)` | HMAC-SHA256 helper |

### Not yet covered

SSO connection and SCIM directory reads are exposed in the OpenAPI spec only
behind the **session/operator** bearer scheme (not the `sk_` API-key scheme),
so they are intentionally omitted from this server SDK. Per-user create/update/
delete is likewise not part of the public `sk_` surface. These will be added if
and when API-key-scoped routes ship.

## Develop

```bash
mvn package   # compile + run tests + build jar
mvn test      # tests only
```

## License

MIT
