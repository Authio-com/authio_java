package com.authio;

/**
 * A typed Authio API error. Mirrors the wire {@code Error} schema
 * ({@code {code, message, request_id}}) plus the HTTP status code.
 *
 * <p>Network/transport failures are surfaced as {@code AuthioError} with
 * {@code status == 0} and a code of {@code "network_error"}.
 */
public class AuthioError extends RuntimeException {

  private final String code;
  private final int status;
  private final String requestId;

  public AuthioError(String code, String message, int status, String requestId) {
    super(message);
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }

  public AuthioError(String code, String message, int status, String requestId, Throwable cause) {
    super(message, cause);
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }

  /** Stable machine-readable error code, e.g. {@code membership_not_found}. */
  public String getCode() {
    return code;
  }

  /** HTTP status code. {@code 0} for transport/network failures. */
  public int getStatus() {
    return status;
  }

  /** Server-provided correlation id, when present. */
  public String getRequestId() {
    return requestId;
  }

  @Override
  public String toString() {
    return "AuthioError{code=" + code + ", status=" + status
        + ", requestId=" + requestId + ", message=" + getMessage() + "}";
  }
}
