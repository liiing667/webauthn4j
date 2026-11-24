package com.webauthn4j.async.metadata;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.MetadataBLOBPayloadEntry;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.util.internal.MetadataBLOBUtil;
import com.webauthn4j.metadata.util.internal.MetadataStatementUtil;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.webauthn4j.metadata.MetadataBLOBBasedMetadataStatementRepository.matchAttestationCertificateKeyIdentifier;

public class MetadataBLOBBasedMetadataStatementAsyncRepository implements MetadataStatementAsyncRepository{

    private final List<MetadataBLOBAsyncProvider> metadataBLOBAsyncProviders;

    private boolean notFidoCertifiedAllowed = false;
    private boolean selfAssertionSubmittedAllowed = false;

    public MetadataBLOBBasedMetadataStatementAsyncRepository(MetadataBLOBAsyncProvider... metadataBLOBAsyncProviders) {
        this.metadataBLOBAsyncProviders = Arrays.asList(metadataBLOBAsyncProviders);
    }

    @Override
    public CompletionStage<Set<MetadataStatement>> find(AAGUID aaguid) {
        return collectEntries()
                .thenApply(entries -> entries
                        .filter(entry -> Objects.equals(entry.getAaguid(), aaguid))
                        .collect(Collectors.toList()))
                .thenApply(this::toMetadataStatements);
    }

    @Override
    public CompletionStage<Set<MetadataStatement>> find(byte[] attestationCertificateKeyIdentifier) {
        return collectEntries()
                .thenApply(entries -> entries
                        .filter(entry -> matchAttestationCertificateKeyIdentifier(entry, attestationCertificateKeyIdentifier))
                        .collect(Collectors.toList()))
                .thenApply(this::toMetadataStatements);
    }

    private CompletionStage<Stream<MetadataBLOBPayloadEntry>> collectEntries() {
        return metadataBLOBAsyncProviders.stream()
                .map(provider -> provider.provide().thenApply(metadataBLOB -> metadataBLOB.getPayload().getEntries().stream()))
                .reduce(CompletableFuture.completedFuture(Stream.empty()), (a, b)-> a.thenCombine(b, Stream::concat));
    }

    private Set<MetadataStatement> toMetadataStatements(List<MetadataBLOBPayloadEntry> entries) {
        // Status reports are checked for every matching entry, regardless of whether the entry was
        // located by AAGUID or by attestation certificate key identifier, so both lookup methods
        // reach the same security conclusion. If multiple sources provide conflicting entries for
        // the same authenticator, the lookup fails closed: a single revoked, compromised or
        // otherwise unacceptable entry invalidates all matching entries.
        boolean allEntriesAcceptable = entries.stream()
                .allMatch(entry -> MetadataBLOBUtil.checkMetadataBLOBPayloadEntry(entry, notFidoCertifiedAllowed, selfAssertionSubmittedAllowed));
        if (!allEntriesAcceptable) {
            return Collections.emptySet();
        }
        return entries.stream()
                .map(MetadataBLOBPayloadEntry::getMetadataStatement)
                .filter(MetadataStatementUtil::checkSurrogateMetadataStatementAttestationRootCertificate)
                .collect(Collectors.toSet());
    }

    public boolean isNotFidoCertifiedAllowed() {
        return notFidoCertifiedAllowed;
    }

    public void setNotFidoCertifiedAllowed(boolean notFidoCertifiedAllowed) {
        this.notFidoCertifiedAllowed = notFidoCertifiedAllowed;
    }

    public boolean isSelfAssertionSubmittedAllowed() {
        return selfAssertionSubmittedAllowed;
    }

    public void setSelfAssertionSubmittedAllowed(boolean selfAssertionSubmittedAllowed) {
        this.selfAssertionSubmittedAllowed = selfAssertionSubmittedAllowed;
    }



}
