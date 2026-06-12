package com.authio;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Verifies Authio access-token JWTs against the remote JWKS.
 *
 * <p>Authio signs tokens with <strong>EdDSA</strong> (Ed25519). This verifier
 * uses the vetted Nimbus JOSE library to parse the compact JWT and the JWKS
 * document, and the JDK 17 built-in {@code Ed25519} primitive for the actual
 * signature check — so no Tink/BouncyCastle dependency is required.
 *
 * <p>JWKS responses are cached in-memory with a TTL; an unknown {@code kid}
 * triggers at most one refetch per cooldown window (handles key rotation).
 */
public final class JwtVerifier {
  private static final Duration CACHE_TTL = Duration.ofMinutes(10);
  private static final Duration REFETCH_COOLDOWN = Duration.ofSeconds(30);

  private final String jwksUrl;
  private final String issuer;
  private final String audience;
  private final HttpClient http;

  private volatile JWKSet cached;
  private volatile Instant fetchedAt = Instant.EPOCH;

  /**
   * @param jwksUrl absolute URL of the JWKS document
   * @param issuer required {@code iss}; when null, issuer is not enforced
   * @param audience required {@code aud}; when null, audience is not enforced
   */
  public JwtVerifier(String jwksUrl, String issuer, String audience) {
    this.jwksUrl = jwksUrl;
    this.issuer = issuer;
    this.audience = audience;
    this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
  }

  /**
   * Verify a token and return its claims. Throws {@link AuthioError} (code
   * {@code invalid_token}) on any failure: bad signature, expiry, unknown key,
   * or issuer/audience mismatch.
   */
  public Map<String, Object> verify(String token) {
    SignedJWT jwt;
    try {
      jwt = SignedJWT.parse(token);
    } catch (Exception ex) {
      throw invalid("malformed JWT", ex);
    }

    String alg = jwt.getHeader().getAlgorithm() == null
        ? null
        : jwt.getHeader().getAlgorithm().getName();
    if (!"EdDSA".equals(alg)) {
      throw invalid("unexpected JWS algorithm: " + alg, null);
    }

    String kid = jwt.getHeader().getKeyID();
    PublicKey key = resolveKey(kid);
    if (!verifySignature(jwt, key)) {
      throw invalid("signature verification failed", null);
    }

    JWTClaimsSet claims;
    try {
      claims = jwt.getJWTClaimsSet();
    } catch (Exception ex) {
      throw invalid("unreadable claims", ex);
    }
    validateTemporalAndScope(claims);

    Map<String, Object> out = new HashMap<>(claims.getClaims());
    if (claims.getExpirationTime() != null) {
      out.put("exp", claims.getExpirationTime().toInstant().getEpochSecond());
    }
    if (claims.getIssueTime() != null) {
      out.put("iat", claims.getIssueTime().toInstant().getEpochSecond());
    }
    return out;
  }

  private void validateTemporalAndScope(JWTClaimsSet claims) {
    Date now = new Date();
    Date exp = claims.getExpirationTime();
    if (exp != null && now.after(new Date(exp.getTime() + 60_000L))) {
      throw invalid("token expired", null);
    }
    Date nbf = claims.getNotBeforeTime();
    if (nbf != null && now.before(new Date(nbf.getTime() - 60_000L))) {
      throw invalid("token not yet valid", null);
    }
    if (issuer != null && !issuer.equals(claims.getIssuer())) {
      throw invalid("issuer mismatch", null);
    }
    if (audience != null && (claims.getAudience() == null || !claims.getAudience().contains(audience))) {
      throw invalid("audience mismatch", null);
    }
    if (claims.getSubject() == null || claims.getSubject().isEmpty()) {
      throw invalid("missing sub claim", null);
    }
  }

  private PublicKey resolveKey(String kid) {
    JWKSet set = jwks(false);
    JWK jwk = (kid != null) ? set.getKeyByKeyId(kid) : firstOkp(set);
    if (jwk == null) {
      // Possible rotation: force a refetch (rate-limited) and retry once.
      set = jwks(true);
      jwk = (kid != null) ? set.getKeyByKeyId(kid) : firstOkp(set);
    }
    if (jwk == null) {
      throw invalid("no signing key for kid=" + kid, null);
    }
    if (!(jwk instanceof OctetKeyPair okp) || !Curve.Ed25519.equals(okp.getCurve())) {
      throw invalid("signing key is not an Ed25519 OKP", null);
    }
    try {
      return toEd25519PublicKey(okp.getDecodedX());
    } catch (Exception ex) {
      throw invalid("could not decode signing key", ex);
    }
  }

  private static JWK firstOkp(JWKSet set) {
    for (JWK k : set.getKeys()) {
      if (k instanceof OctetKeyPair) {
        return k;
      }
    }
    return null;
  }

  private boolean verifySignature(SignedJWT jwt, PublicKey key) {
    try {
      String[] parts = jwt.getParsedString().split("\\.");
      byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
      byte[] sig = Base64.getUrlDecoder().decode(parts[2]);
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(key);
      verifier.update(signingInput);
      return verifier.verify(sig);
    } catch (Exception ex) {
      return false;
    }
  }

  /**
   * Build a JDK {@link PublicKey} from the 32-byte little-endian Ed25519 public
   * key (RFC 8032 §5.1.2 encoding: MSB of the final byte carries the x sign).
   */
  private static PublicKey toEd25519PublicKey(byte[] raw) throws Exception {
    byte[] le = raw.clone();
    boolean xOdd = (le[le.length - 1] & 0x80) != 0;
    le[le.length - 1] &= 0x7f;
    // Reverse to big-endian for BigInteger.
    for (int i = 0, j = le.length - 1; i < j; i++, j--) {
      byte t = le[i];
      le[i] = le[j];
      le[j] = t;
    }
    BigInteger y = new BigInteger(1, le);
    NamedParameterSpec params = new NamedParameterSpec("Ed25519");
    EdECPoint point = new EdECPoint(xOdd, y);
    EdECPublicKeySpec spec = new EdECPublicKeySpec(params, point);
    return KeyFactory.getInstance("Ed25519").generatePublic(spec);
  }

  private JWKSet jwks(boolean forceRefetch) {
    JWKSet local = cached;
    boolean fresh = local != null
        && Instant.now().isBefore(fetchedAt.plus(CACHE_TTL));
    if (!forceRefetch && fresh) {
      return local;
    }
    if (forceRefetch && Instant.now().isBefore(fetchedAt.plus(REFETCH_COOLDOWN)) && local != null) {
      return local;
    }
    synchronized (this) {
      if (!forceRefetch && cached != null && Instant.now().isBefore(fetchedAt.plus(CACHE_TTL))) {
        return cached;
      }
      try {
        HttpRequest req =
            HttpRequest.newBuilder()
                .uri(URI.create(jwksUrl))
                .timeout(Duration.ofSeconds(10))
                .header("Accept", "application/json")
                .header("User-Agent", Version.USER_AGENT)
                .GET()
                .build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() != 200) {
          throw new AuthioError(
              "jwks_fetch_failed", "JWKS endpoint returned " + res.statusCode(), res.statusCode(), null);
        }
        cached = JWKSet.parse(res.body());
        fetchedAt = Instant.now();
        return cached;
      } catch (AuthioError e) {
        throw e;
      } catch (Exception ex) {
        if (cached != null) {
          return cached;
        }
        throw new AuthioError("jwks_fetch_failed", ex.getMessage(), 0, null, ex);
      }
    }
  }

  private static AuthioError invalid(String message, Throwable cause) {
    return new AuthioError("invalid_token", "authio: " + message, 401, null, cause);
  }
}
