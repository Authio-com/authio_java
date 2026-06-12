package com.authio;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;

/**
 * Shared Jackson {@link ObjectMapper}, configured to mirror the Authio wire
 * contract: snake_case JSON keys, field-based (de)serialization, and lenient
 * decoding so additive server fields never break older SDKs.
 */
final class Json {
  private Json() {}

  static final ObjectMapper MAPPER = build();

  private static ObjectMapper build() {
    ObjectMapper m = new ObjectMapper();
    m.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
    m.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
    m.setVisibility(PropertyAccessor.GETTER, JsonAutoDetect.Visibility.NONE);
    m.setVisibility(PropertyAccessor.IS_GETTER, JsonAutoDetect.Visibility.NONE);
    m.setVisibility(PropertyAccessor.SETTER, JsonAutoDetect.Visibility.NONE);
    m.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    m.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    return m;
  }
}
