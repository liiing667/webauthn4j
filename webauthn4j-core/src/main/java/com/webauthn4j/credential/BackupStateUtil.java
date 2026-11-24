/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.credential;

import org.jetbrains.annotations.Nullable;

/**
 * Defines the invariants shared by every path that constructs, mutates, reads, or restores
 * a credential record's backup eligibility and backup state.
 * <p>
 * A credential cannot be backed up when it is explicitly known not to be backup eligible.
 * Persisted records created before WebAuthn Level 3 may not contain these fields at all,
 * so {@code null} values are treated as unknown and remain valid for backward compatibility.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3 § 7.2 Step 18</a>
 */
public final class BackupStateUtil {

    public static final String INCONSISTENT_BACKUP_STATE_MESSAGE =
            "backupState must not be true when backupEligible is false";

    private BackupStateUtil() {
    }

    /**
     * Returns whether the given backup eligibility and backup state pair is consistent.
     * <p>
     * {@code (false, true)} is the only contradictory combination. {@code null} means that
     * the value is unavailable, which is allowed for records persisted by older versions.
     *
     * @param backupEligible the backup eligibility value, may be null
     * @param backedUp       the backup state value, may be null
     * @return {@code true} if the pair does not contradict itself
     */
    public static boolean isConsistent(@Nullable Boolean backupEligible, @Nullable Boolean backedUp) {
        return !Boolean.FALSE.equals(backupEligible) || !Boolean.TRUE.equals(backedUp);
    }

    /**
     * Validates that the given backup eligibility and backup state pair is consistent.
     *
     * @param backupEligible the backup eligibility value, may be null
     * @param backedUp       the backup state value, may be null
     * @throws IllegalArgumentException if the pair is contradictory
     */
    public static void validate(@Nullable Boolean backupEligible, @Nullable Boolean backedUp) {
        if (!isConsistent(backupEligible, backedUp)) {
            throw new IllegalArgumentException(INCONSISTENT_BACKUP_STATE_MESSAGE);
        }
    }
}
