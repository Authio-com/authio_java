package com.authio.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** Lifecycle state of a {@link Membership}. */
public enum MembershipStatus {
  INVITED("invited"),
  ACTIVE("active"),
  SUSPENDED("suspended"),
  DEACTIVATED("deactivated"),
  /** Forward-compatible fallback for values added after this SDK shipped. */
  UNKNOWN("unknown");

  private final String wire;

  MembershipStatus(String wire) {
    this.wire = wire;
  }

  @JsonValue
  public String wire() {
    return wire;
  }

  @JsonCreator
  public static MembershipStatus from(String value) {
    if (value == null) {
      return null;
    }
    for (MembershipStatus s : values()) {
      if (s.wire.equals(value)) {
        return s;
      }
    }
    return UNKNOWN;
  }
}
