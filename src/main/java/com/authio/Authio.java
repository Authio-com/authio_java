package com.authio;

import com.authio.models.ClientCredentialsInput;
import com.authio.models.TokenResponse;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The entrypoint for server-side calls into Authio.
 *
 * <p>Multi-org-first: a verified {@link Session} always identifies the user
 * ({@code userId}); the active organization ({@code orgId}) is only set once
 * the user has selected one of their memberships.
 *
 * <pre>{@code
 * Authio authio = Authio.builder(System.getenv("AUTHIO_SECRET_KEY")).buildClient();
 * Session session = authio.sessions.verify(accessToken);
 * if (session != null) {
 *   UserList users = authio.users.list();
 * }
 * }</pre>
 */
public final class Authio {
  /** Default path of the JWKS document on the auth-core origin. */
  private static final String JWKS_PATH = "/v1/auth/.well-known/jwks.json";
  /** Auth-core OAuth token endpoint. */
  private static final String TOKEN_PATH = "/v1/auth/token";

  private final AuthioOptions options;
  private final Transport transport;
  private final JwtVerifier verifier;

  public final UsersApi users;
  public final OrganizationsApi organizations;
  public final MembershipsApi memberships;
  public final InvitesApi invites;
  public final WebhooksApi webhooks;
  public final EventsApi events;
  public final PortalApi portal;
  public final SessionsApi sessions;

  public Authio(AuthioOptions options) {
    this.options = options;
    this.transport = new Transport(options);
    this.verifier =
        new JwtVerifier(options.authCoreUrl + JWKS_PATH, options.jwtIssuer, options.jwtAudience);
    this.users = new UsersApi(transport);
    this.organizations = new OrganizationsApi(transport);
    this.memberships = new MembershipsApi(transport);
    this.invites = new InvitesApi(transport);
    this.webhooks = new WebhooksApi(transport);
    this.events = new EventsApi(transport);
    this.portal = new PortalApi(transport);
    this.sessions = new SessionsApi(verifier);
  }

  /** Convenience: {@code Authio.builder(apiKey).build()...}. */
  public static AuthioOptions.Builder builder(String apiKey) {
    return AuthioOptions.builder(apiKey);
  }

  public AuthioOptions options() {
    return options;
  }

  /** The shared JWT verifier (for verifying widget/M2M tokens directly). */
  public JwtVerifier verifier() {
    return verifier;
  }

  /**
   * Exchange OAuth client credentials for a short-lived access token (M2M).
   * Targets auth-core's {@code POST /v1/auth/token} as
   * {@code application/x-www-form-urlencoded} per the OpenAPI contract.
   */
  public TokenResponse token(ClientCredentialsInput input) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "client_credentials");
    form.put("client_id", input.clientId);
    form.put("client_secret", input.clientSecret);
    if (input.scope != null) {
      form.put("scope", input.scope);
    }
    return transport.postForm(TOKEN_PATH, form, Transport.typeOf(TokenResponse.class));
  }
}
