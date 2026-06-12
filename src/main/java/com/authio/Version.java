package com.authio;

/** SDK version metadata. Stamped into the {@code X-Authio-SDK} header. */
public final class Version {
  private Version() {}

  /** Semantic version of this SDK release. */
  public static final String SDK_VERSION = "0.1.0";

  /** Value sent in the {@code X-Authio-SDK} request header. */
  public static final String SDK_HEADER = "java/" + SDK_VERSION;

  /** Value sent in the {@code User-Agent} request header. */
  public static final String USER_AGENT = "authio-java/" + SDK_VERSION;
}
