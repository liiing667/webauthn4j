package com.webauthn4j.async.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorAttestationType;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBPayload;
import com.webauthn4j.metadata.data.MetadataBLOBPayloadEntry;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.data.toc.AuthenticatorStatus;
import com.webauthn4j.metadata.data.toc.StatusReport;
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MetadataBLOBBasedMetadataStatementAsyncRepositoryTest {

    @TempDir
    Path tempDir;

    @Test
    void find_by_aaguid_test() throws IOException, ExecutionException, InterruptedException {
        AAGUID aaguid = new AAGUID("9c835346-796b-4c27-8898-d6032f515cc5");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBAsyncProvider metadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(metadataBLOBAsyncProvider);
        assertThat(target.find(aaguid).toCompletableFuture().get()).hasSize(1);
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_test() throws IOException, ExecutionException, InterruptedException {
        byte[] attestationCertificateKeyIdentifier = HexUtil.decode("1434d2f277fe479c35ddf6aa4d08a07cbce99dd7");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBAsyncProvider metadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(metadataBLOBAsyncProvider);

        assertThat(target.find(attestationCertificateKeyIdentifier).toCompletableFuture().get()).isEmpty();

        target.setNotFidoCertifiedAllowed(true);
        assertThat(target.find(attestationCertificateKeyIdentifier).toCompletableFuture().get()).hasSize(1);
    }

    @Test
    void notFidoCertifiedAllowed_test() throws IOException, ExecutionException, InterruptedException {
        AAGUID aaguid = new AAGUID("3789da91-f943-46bc-95c3-50ea2012f03a");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBAsyncProvider metadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(metadataBLOBAsyncProvider);
        target.setNotFidoCertifiedAllowed(false);
        assertThat(target.isNotFidoCertifiedAllowed()).isFalse();
        assertThat(target.find(aaguid).toCompletableFuture().get()).isEmpty();
        target.setNotFidoCertifiedAllowed(true);
        assertThat(target.find(aaguid).toCompletableFuture().get()).hasSize(1);
        assertThat(target.isNotFidoCertifiedAllowed()).isTrue();
    }

    @Test
    void selfAssertionSubmittedAllowed_test() throws IOException, ExecutionException, InterruptedException {
        AAGUID aaguid = new AAGUID("01d993d9-33d7-4db5-a7a9-7edc56ddfdb5");
        Path blobPath = new File("src/test/resources/integration/component/test-blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBAsyncProvider metadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(metadataBLOBAsyncProvider);

        target.setSelfAssertionSubmittedAllowed(false);
        assertThat(target.isSelfAssertionSubmittedAllowed()).isFalse();
        assertThat(target.find(aaguid).toCompletableFuture().get()).isEmpty();

        target.setSelfAssertionSubmittedAllowed(true);
        assertThat(target.find(aaguid).toCompletableFuture().get()).hasSize(1);
        assertThat(target.isSelfAssertionSubmittedAllowed()).isTrue();
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_rejects_untrusted_status_test() throws ExecutionException, InterruptedException {
        AAGUID aaguid = new AAGUID(UUID.randomUUID());
        String keyIdentifier = keyIdentifier();
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(
                provider(entry(aaguid, keyIdentifier, AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE)));

        assertThat(target.find(HexUtil.decode(keyIdentifier)).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_does_not_publish_partial_result_when_sources_disagree_test() throws ExecutionException, InterruptedException {
        AAGUID aaguid = new AAGUID(UUID.randomUUID());
        String keyIdentifier = keyIdentifier();
        MetadataBLOBAsyncProvider trustedProvider = provider(entry(aaguid, keyIdentifier, AuthenticatorStatus.FIDO_CERTIFIED_L1));
        MetadataBLOBAsyncProvider compromisingProvider = provider(entry(aaguid, keyIdentifier, AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE));
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(
                trustedProvider, compromisingProvider);

        assertThat(target.find(aaguid).toCompletableFuture().get()).isEmpty();
        assertThat(target.find(HexUtil.decode(keyIdentifier)).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_by_aaguid_rejects_when_related_key_identifier_is_untrusted_test() throws ExecutionException, InterruptedException {
        AAGUID aaguid = new AAGUID(UUID.randomUUID());
        String keyIdentifier = keyIdentifier();
        MetadataBLOBAsyncProvider trustedProvider = provider(entry(aaguid, keyIdentifier, AuthenticatorStatus.FIDO_CERTIFIED_L1));
        MetadataBLOBAsyncProvider compromisingProvider = provider(entry(null, keyIdentifier, AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE));
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(
                trustedProvider, compromisingProvider);

        assertThat(target.find(aaguid).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_by_key_identifier_rejects_when_related_aaguid_is_untrusted_test() throws ExecutionException, InterruptedException {
        AAGUID aaguid = new AAGUID(UUID.randomUUID());
        String keyIdentifier = keyIdentifier();
        MetadataBLOBAsyncProvider trustedProvider = provider(entry(aaguid, keyIdentifier, AuthenticatorStatus.FIDO_CERTIFIED_L1));
        MetadataBLOBAsyncProvider compromisingProvider = provider(entry(aaguid, null, AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE));
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(
                trustedProvider, compromisingProvider);

        assertThat(target.find(HexUtil.decode(keyIdentifier)).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_preserves_source_failure_semantics_test() {
        AAGUID aaguid = new AAGUID(UUID.randomUUID());
        MetadataBLOBAsyncProvider trustedProvider = provider(entry(aaguid, null, AuthenticatorStatus.FIDO_CERTIFIED_L1));
        MetadataBLOBAsyncProvider failingProvider = mock(MetadataBLOBAsyncProvider.class);
        when(failingProvider.provide()).thenReturn(CompletableFuture.failedFuture(new IllegalStateException("source failure")));
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(
                trustedProvider, failingProvider);

        assertThatThrownBy(() -> target.find(aaguid).toCompletableFuture().get())
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(IllegalStateException.class);
    }

    private static String keyIdentifier() {
        return "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    }

    private static MetadataBLOBAsyncProvider provider(MetadataBLOBPayloadEntry... entries) {
        MetadataBLOBAsyncProvider provider = mock(MetadataBLOBAsyncProvider.class);
        MetadataBLOB metadataBLOB = mock(MetadataBLOB.class);
        MetadataBLOBPayload metadataBLOBPayload = mock(MetadataBLOBPayload.class);
        when(provider.provide()).thenReturn(CompletableFuture.completedFuture(metadataBLOB));
        when(metadataBLOB.getPayload()).thenReturn(metadataBLOBPayload);
        when(metadataBLOBPayload.getEntries()).thenReturn(Arrays.asList(entries));
        return provider;
    }

    private static MetadataBLOBPayloadEntry entry(AAGUID aaguid, String keyIdentifier, AuthenticatorStatus status) {
        List<String> keyIdentifiers = keyIdentifier == null ? null : Collections.singletonList(keyIdentifier);

        MetadataStatement metadataStatement = mock(MetadataStatement.class);
        when(metadataStatement.getAaguid()).thenReturn(aaguid);
        when(metadataStatement.getAttestationCertificateKeyIdentifiers()).thenReturn(keyIdentifiers);
        when(metadataStatement.getAttestationTypes()).thenReturn(Collections.singletonList(AuthenticatorAttestationType.BASIC_FULL));
        when(metadataStatement.getAttestationRootCertificates()).thenReturn(Collections.emptyList());

        StatusReport statusReport = mock(StatusReport.class);
        when(statusReport.getStatus()).thenReturn(status);

        MetadataBLOBPayloadEntry entry = mock(MetadataBLOBPayloadEntry.class);
        when(entry.getAaguid()).thenReturn(aaguid);
        when(entry.getAttestationCertificateKeyIdentifiers()).thenReturn(keyIdentifiers);
        when(entry.getMetadataStatement()).thenReturn(metadataStatement);
        when(entry.getStatusReports()).thenReturn(Collections.singletonList(statusReport));
        return entry;
    }

}
