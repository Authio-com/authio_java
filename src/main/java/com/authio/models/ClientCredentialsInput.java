package com.authio.models;

/**
 * Input for the M2M {@code client_credentials} token exchange. Sent to
 * auth-core's {@code POST /v1/auth/token} as
 * {@code application/x-www-form-urlencoded} per the OpenAPI contract.
 */
public final class ClientCredentialsInput {
  public final String clientId;
  public final String clientSecret;
  public String scope;

  public ClientCredentialsInput(String clientId, String clientSecret) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
  }

  public ClientCredentialsInput scope(String scope) {
    this.scope = scope;
    return this;
  }
}
