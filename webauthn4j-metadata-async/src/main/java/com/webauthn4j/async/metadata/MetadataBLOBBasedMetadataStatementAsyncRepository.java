package com.webauthn4j.async.metadata;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.MetadataBLOBPayloadEntry;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.util.internal.MetadataBLOBUtil;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Predicate;
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
        return find(entry -> MetadataBLOBUtil.matchesAAGUID(entry, aaguid));
    }

    @Override
    public CompletionStage<Set<MetadataStatement>> find(byte[] attestationCertificateKeyIdentifier) {
        return find(entry -> matchAttestationCertificateKeyIdentifier(entry, attestationCertificateKeyIdentifier));
    }

    private CompletionStage<Set<MetadataStatement>> find(Predicate<MetadataBLOBPayloadEntry> entryMatcher) {
        return metadataBLOBAsyncProviders.stream()
                .map(provider -> provider.provide().thenApply(metadataBLOB -> metadataBLOB.getPayload().getEntries().stream()))
                .reduce(CompletableFuture.completedFuture(Stream.empty()),
                        (a, b)-> a.thenCombine(b, Stream::concat)
                ).thenApply(entries -> {
                    List<MetadataBLOBPayloadEntry> metadataBLOBPayloadEntries = entries
                            .filter(Objects::nonNull)
                            .collect(Collectors.toList());
                    return MetadataBLOBUtil.findMetadataStatements(
                            metadataBLOBPayloadEntries, entryMatcher, notFidoCertifiedAllowed, selfAssertionSubmittedAllowed);
                });
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
