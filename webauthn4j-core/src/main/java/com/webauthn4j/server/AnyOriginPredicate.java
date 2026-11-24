package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;

/**
 * An {@link OriginPredicate} implementation that accepts any origin.
 * <p>
 * This predicate always returns {@code true} for any origin value, effectively
 * bypassing origin validation. This can be useful for testing or development
 * environments, but should <strong>never be used in production</strong> as it
 * violates the security model of WebAuthn.
 * <p>
 * According to WebAuthn Level 3 § 13.4.9, Relying Parties must validate that
 * origins match their expectations to prevent cross-origin attacks.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-validating-origin">WebAuthn Level 3 § 13.4.9 Validating the origin of a credential</a>
 */
public class AnyOriginPredicate implements OriginPredicate {
    /**
     * Returns {@code true} for any non-null origin, accepting it regardless of its value.
     * A missing origin is still rejected: accepting {@code null} would turn the absence of
     * the cross-origin evidence into permission, which is unsafe.
     *
     * @param origin the origin to test (ignored)
     * @return {@code true} if {@code origin} is not null, {@code false} otherwise
     */
    @Override
    public boolean test(Origin origin) {
        return origin != null;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        return true;
    }

    @Override
    public int hashCode() {
        return 31;
    }

    @Override
    public String toString() {
        return "(any origin)";
    }
}
