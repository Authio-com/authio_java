package com.authio.models;

/** OAuth 2.0 token endpoint response (client_credentials grant). */
public class TokenResponse {
  public String accessToken;
  public String tokenType;
  public long expiresIn;
  public String scope;
}
