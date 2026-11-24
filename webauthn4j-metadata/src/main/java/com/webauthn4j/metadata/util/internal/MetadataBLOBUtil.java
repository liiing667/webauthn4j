package com.webauthn4j.metadata.util.internal;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.MetadataBLOBPayloadEntry;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.data.toc.StatusReport;
import com.webauthn4j.util.HexUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class MetadataBLOBUtil {

    private MetadataBLOBUtil(){}

    public static boolean checkMetadataBLOBPayloadEntry(@NotNull MetadataBLOBPayloadEntry metadataBLOBPayloadEntry, boolean notFidoCertifiedAllowed, boolean selfAssertionSubmittedAllowed) {
        List<StatusReport> statusReports = metadataBLOBPayloadEntry.getStatusReports();
        for (StatusReport report : statusReports) {
            switch (report.getStatus()) {
                //Info statuses
                case UPDATE_AVAILABLE:
                    // UPDATE_AVAILABLE itself doesn't mean security issue. If security related update is available,
                    // corresponding status report is expected to be added to the report list.
                    break;

                //Certification Related statuses
                case FIDO_CERTIFIED:
                case FIDO_CERTIFIED_L1:
                case FIDO_CERTIFIED_L1_PLUS:
                case FIDO_CERTIFIED_L2:
                case FIDO_CERTIFIED_L2_PLUS:
                case FIDO_CERTIFIED_L3:
                case FIDO_CERTIFIED_L3_PLUS:
                    break;
                case NOT_FIDO_CERTIFIED:
                    if (notFidoCertifiedAllowed) {
                        break;
                    }
                    else {
                        return false;
                    }
                case SELF_ASSERTION_SUBMITTED:
                    if (selfAssertionSubmittedAllowed) {
                        break;
                    }
                    else {
                        return false;
                    }

                    // Security Notification statuses
                case ATTESTATION_KEY_COMPROMISE:
                case USER_VERIFICATION_BYPASS:
                case USER_KEY_REMOTE_COMPROMISE:
                case USER_KEY_PHYSICAL_COMPROMISE:
                case REVOKED:
                default:
                    return false;
            }
        }
        return true;
    }

    /**
     * Checks every entry that belongs to the same authenticator. The result is only trusted when all of the
     * entries reported by all metadata sources are trusted. Returning a subset would allow a trusted entry from
     * one source to hide an untrusted entry reported by another source.
     *
     * @param metadataBLOBPayloadEntries entries reported by all metadata sources
     * @param notFidoCertifiedAllowed whether NOT_FIDO_CERTIFIED is allowed
     * @param selfAssertionSubmittedAllowed whether SELF_ASSERTION_SUBMITTED is allowed
     * @return true if all entries are trusted
     */
    public static boolean checkMetadataBLOBPayloadEntries(
            @NotNull List<MetadataBLOBPayloadEntry> metadataBLOBPayloadEntries,
            boolean notFidoCertifiedAllowed,
            boolean selfAssertionSubmittedAllowed) {
        for (MetadataBLOBPayloadEntry metadataBLOBPayloadEntry : metadataBLOBPayloadEntries) {
            if (metadataBLOBPayloadEntry == null
                    || !checkMetadataBLOBPayloadEntry(metadataBLOBPayloadEntry, notFidoCertifiedAllowed, selfAssertionSubmittedAllowed)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Finds metadata statements for the given entry matcher. Entries are grouped by the authenticator identity
     * (AAGUID and attestation certificate key identifiers) across all metadata sources. A statement is only
     * returned when every entry in the identity group is trusted; otherwise no result is published.
     *
     * @param metadataBLOBPayloadEntries entries reported by all metadata sources
     * @param entryMatcher matcher selecting entries for the requested identity
     * @param notFidoCertifiedAllowed whether NOT_FIDO_CERTIFIED is allowed
     * @param selfAssertionSubmittedAllowed whether SELF_ASSERTION_SUBMITTED is allowed
     * @return trusted metadata statements for the requested identity
     */
    public static Set<MetadataStatement> findMetadataStatements(
            @NotNull List<MetadataBLOBPayloadEntry> metadataBLOBPayloadEntries,
            @NotNull Predicate<MetadataBLOBPayloadEntry> entryMatcher,
            boolean notFidoCertifiedAllowed,
            boolean selfAssertionSubmittedAllowed) {
        List<MetadataBLOBPayloadEntry> matchedEntries = metadataBLOBPayloadEntries.stream()
                .filter(Objects::nonNull)
                .filter(entryMatcher)
                .collect(Collectors.toList());
        if (matchedEntries.isEmpty()) {
            return new HashSet<>();
        }

        List<MetadataBLOBPayloadEntry> relatedEntries = findIdentityRelatedEntries(metadataBLOBPayloadEntries, matchedEntries);
        // A trusted result from one source must not mask an untrusted report from another source.
        if (!checkMetadataBLOBPayloadEntries(relatedEntries, notFidoCertifiedAllowed, selfAssertionSubmittedAllowed)) {
            return new HashSet<>();
        }

        return matchedEntries.stream()
                .map(MetadataBLOBPayloadEntry::getMetadataStatement)
                .filter(Objects::nonNull)
                .filter(MetadataStatementUtil::checkSurrogateMetadataStatementAttestationRootCertificate)
                .collect(Collectors.toSet());
    }

    public static boolean matchesAAGUID(@Nullable MetadataBLOBPayloadEntry metadataBLOBPayloadEntry, @Nullable AAGUID aaguid) {
        if (metadataBLOBPayloadEntry == null || aaguid == null) {
            return false;
        }
        return getAAGUIDs(metadataBLOBPayloadEntry).contains(aaguid);
    }

    public static boolean matchesAttestationCertificateKeyIdentifier(
            @Nullable MetadataBLOBPayloadEntry metadataBLOBPayloadEntry,
            @Nullable byte[] attestationCertificateKeyIdentifier) {
        if (metadataBLOBPayloadEntry == null || attestationCertificateKeyIdentifier == null) {
            return false;
        }
        return getAttestationCertificateKeyIdentifiers(metadataBLOBPayloadEntry)
                .contains(HexUtil.encodeToString(attestationCertificateKeyIdentifier));
    }

    static Set<AAGUID> getAAGUIDs(@Nullable MetadataBLOBPayloadEntry metadataBLOBPayloadEntry) {
        if (metadataBLOBPayloadEntry == null) {
            return Collections.emptySet();
        }
        Set<AAGUID> aaguids = new HashSet<>();
        if (metadataBLOBPayloadEntry.getAaguid() != null) {
            aaguids.add(metadataBLOBPayloadEntry.getAaguid());
        }
        MetadataStatement metadataStatement = metadataBLOBPayloadEntry.getMetadataStatement();
        if (metadataStatement != null && metadataStatement.getAaguid() != null) {
            aaguids.add(metadataStatement.getAaguid());
        }
        return aaguids;
    }

    static Set<String> getAttestationCertificateKeyIdentifiers(@Nullable MetadataBLOBPayloadEntry metadataBLOBPayloadEntry) {
        if (metadataBLOBPayloadEntry == null) {
            return Collections.emptySet();
        }
        Set<String> keyIdentifiers = new HashSet<>();
        addKeyIdentifiers(keyIdentifiers, metadataBLOBPayloadEntry.getAttestationCertificateKeyIdentifiers());
        MetadataStatement metadataStatement = metadataBLOBPayloadEntry.getMetadataStatement();
        if (metadataStatement != null) {
            addKeyIdentifiers(keyIdentifiers, metadataStatement.getAttestationCertificateKeyIdentifiers());
        }
        return keyIdentifiers;
    }

    private static void addKeyIdentifiers(@NotNull Set<String> destination, @Nullable List<String> keyIdentifiers) {
        if (keyIdentifiers == null) {
            return;
        }
        for (String keyIdentifier : keyIdentifiers) {
            if (keyIdentifier == null) {
                continue;
            }
            try {
                destination.add(HexUtil.encodeToString(HexUtil.decode(keyIdentifier)));
            }
            catch (IllegalArgumentException e) {
                // Malformed identifiers cannot match a valid certificate key identifier.
                destination.add(keyIdentifier);
            }
        }
    }

    private static List<MetadataBLOBPayloadEntry> findIdentityRelatedEntries(
            @NotNull List<MetadataBLOBPayloadEntry> metadataBLOBPayloadEntries,
            @NotNull List<MetadataBLOBPayloadEntry> matchedEntries) {
        Map<AAGUID, List<MetadataBLOBPayloadEntry>> entriesByAaguid = new HashMap<>();
        Map<String, List<MetadataBLOBPayloadEntry>> entriesByKeyIdentifier = new HashMap<>();
        for (MetadataBLOBPayloadEntry entry : metadataBLOBPayloadEntries) {
            for (AAGUID aaguid : getAAGUIDs(entry)) {
                entriesByAaguid.computeIfAbsent(aaguid, key -> new ArrayList<>()).add(entry);
            }
            for (String keyIdentifier : getAttestationCertificateKeyIdentifiers(entry)) {
                entriesByKeyIdentifier.computeIfAbsent(keyIdentifier, key -> new ArrayList<>()).add(entry);
            }
        }

        Set<MetadataBLOBPayloadEntry> relatedEntries = new LinkedHashSet<>(matchedEntries);
        Deque<MetadataBLOBPayloadEntry> queue = new ArrayDeque<>(matchedEntries);
        Set<AAGUID> visitedAaguids = new HashSet<>();
        Set<String> visitedKeyIdentifiers = new HashSet<>();
        while (!queue.isEmpty()) {
            MetadataBLOBPayloadEntry entry = queue.removeFirst();
            for (AAGUID aaguid : getAAGUIDs(entry)) {
                if (visitedAaguids.add(aaguid)) {
                    enqueueRelatedEntries(entriesByAaguid.get(aaguid), queue, relatedEntries);
                }
            }
            for (String keyIdentifier : getAttestationCertificateKeyIdentifiers(entry)) {
                if (visitedKeyIdentifiers.add(keyIdentifier)) {
                    enqueueRelatedEntries(entriesByKeyIdentifier.get(keyIdentifier), queue, relatedEntries);
                }
            }
        }
        return new ArrayList<>(relatedEntries);
    }

    private static void enqueueRelatedEntries(
            @Nullable List<MetadataBLOBPayloadEntry> entries,
            @NotNull Deque<MetadataBLOBPayloadEntry> queue,
            @NotNull Set<MetadataBLOBPayloadEntry> relatedEntries) {
        if (entries == null) {
            return;
        }
        for (MetadataBLOBPayloadEntry entry : entries) {
            if (relatedEntries.add(entry)) {
                queue.addLast(entry);
            }
        }
    }
}
