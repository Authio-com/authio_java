package com.authio;

import java.time.Duration;

/**
 * Configuration for an {@link Authio} client. Construct via {@link #builder}.
 *
 * <p>Defaults target the production API ({@code https://api.authio.com}, the
 * single server declared in the OpenAPI contract). The auth-core surface
 * ({@code /v1/auth/token} + JWKS) lives on the same origin by default; override
 * {@link Builder#authCoreUrl} for split deployments.
 */
public final class AuthioOptions {
  public static final String DEFAULT_API_URL = "https://api.authio.com";

  final String apiKey;
  final String apiUrl;
  final String authCoreUrl;
  final String jwtIssuer;
  final String jwtAudience;
  final Duration requestTimeout;
  final Duration connectTimeout;
  final int maxRetries;
  final Duration retryBaseDelay;

  private AuthioOptions(Builder b) {
    if (b.apiKey == null || b.apiKey.isEmpty()) {
      throw new IllegalArgumentException(
          "Authio: apiKey is required. Pass it directly or set AUTHIO_SECRET_KEY.");
    }
    this.apiKey = b.apiKey;
    this.apiUrl = trimTrailingSlash(b.apiUrl != null ? b.apiUrl : DEFAULT_API_URL);
    this.authCoreUrl = trimTrailingSlash(b.authCoreUrl != null ? b.authCoreUrl : this.apiUrl);
    this.jwtIssuer = b.jwtIssuer;
    this.jwtAudience = b.jwtAudience;
    this.requestTimeout = b.requestTimeout != null ? b.requestTimeout : Duration.ofSeconds(30);
    this.connectTimeout = b.connectTimeout != null ? b.connectTimeout : Duration.ofSeconds(10);
    this.maxRetries = b.maxRetries;
    this.retryBaseDelay = b.retryBaseDelay != null ? b.retryBaseDelay : Duration.ofMillis(250);
  }

  private static String trimTrailingSlash(String s) {
    return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
  }

  public static Builder builder(String apiKey) {
    return new Builder(apiKey);
  }

  public static final class Builder {
    private String apiKey;
    private String apiUrl;
    private String authCoreUrl;
    private String jwtIssuer;
    private String jwtAudience;
    private Duration requestTimeout;
    private Duration connectTimeout;
    private int maxRetries = 3;
    private Duration retryBaseDelay;

    private Builder(String apiKey) {
      this.apiKey = apiKey;
    }

    /** Management API base URL. Defaults to {@code https://api.authio.com}. */
    public Builder apiUrl(String apiUrl) {
      this.apiUrl = apiUrl;
      return this;
    }

    /** Auth-core base URL (token + JWKS). Defaults to {@link #apiUrl}. */
    public Builder authCoreUrl(String authCoreUrl) {
      this.authCoreUrl = authCoreUrl;
      return this;
    }

    /** Required JWT issuer for session verification. Not enforced when null. */
    public Builder jwtIssuer(String jwtIssuer) {
      this.jwtIssuer = jwtIssuer;
      return this;
    }

    /** Required JWT audience for session verification. Not enforced when null. */
    public Builder jwtAudience(String jwtAudience) {
      this.jwtAudience = jwtAudience;
      return this;
    }

    /** Per-request timeout. Defaults to 30s. */
    public Builder requestTimeout(Duration requestTimeout) {
      this.requestTimeout = requestTimeout;
      return this;
    }

    /** TCP connect timeout. Defaults to 10s. */
    public Builder connectTimeout(Duration connectTimeout) {
      this.connectTimeout = connectTimeout;
      return this;
    }

    /** Max automatic retries on 429/5xx. Defaults to 3 (0 disables). */
    public Builder maxRetries(int maxRetries) {
      this.maxRetries = maxRetries;
      return this;
    }

    /** Base delay for exponential backoff between retries. Defaults to 250ms. */
    public Builder retryBaseDelay(Duration retryBaseDelay) {
      this.retryBaseDelay = retryBaseDelay;
      return this;
    }

    public AuthioOptions build() {
      return new AuthioOptions(this);
    }

    public Authio buildClient() {
      return new Authio(build());
    }
  }
}
