package com.webauthn4j.async.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.metadata.MetadataCodecFallbackRegistrar;
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
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataBLOBBasedMetadataStatementAsyncRepositoryTest {

    private static final byte[] U2F_KEY_IDENTIFIER = HexUtil.decode("7c0903708b87115b0b422def3138c3c864e44573");

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
        byte[] attestationCertificateKeyIdentifier = HexUtil.decode("31116a647069d1493f58fc5b54e5449e2a52d43e");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBAsyncProvider metadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(metadataBLOBAsyncProvider);
        assertThat(target.find(attestationCertificateKeyIdentifier).toCompletableFuture().get()).hasSize(1);
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_filters_notFidoCertified_entry_test() throws IOException, ExecutionException, InterruptedException {
        // NEOWAVE Winkeo FIDO2 (NOT_FIDO_CERTIFIED)
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
    void find_by_attestationCertificateKeyIdentifier_filters_mixed_status_entry_test() throws IOException, ExecutionException, InterruptedException {
        // TrustKey G320 U2F Authenticator (FIDO_CERTIFIED_L1 and NOT_FIDO_CERTIFIED)
        byte[] attestationCertificateKeyIdentifier = HexUtil.decode("32526f73dfca12da9c1d87d6e0adb64e843f73da");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBAsyncProvider metadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(metadataBLOBAsyncProvider);
        assertThat(target.find(attestationCertificateKeyIdentifier).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_filters_revoked_entry_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(createProvider(AuthenticatorStatus.REVOKED));
        assertThat(target.find(U2F_KEY_IDENTIFIER).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_filters_attestation_key_compromise_entry_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(createProvider(AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE));
        assertThat(target.find(U2F_KEY_IDENTIFIER).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_fails_closed_on_conflicting_sources_test() throws ExecutionException, InterruptedException {
        MetadataBLOBAsyncProvider revokedProvider = createProvider(AuthenticatorStatus.REVOKED);
        MetadataBLOBAsyncProvider certifiedProvider = createProvider(AuthenticatorStatus.FIDO_CERTIFIED);
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(revokedProvider, certifiedProvider);
        assertThat(target.find(U2F_KEY_IDENTIFIER).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_returns_certified_entry_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(createProvider(AuthenticatorStatus.FIDO_CERTIFIED));
        assertThat(target.find(U2F_KEY_IDENTIFIER).toCompletableFuture().get()).hasSize(1);
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

    private MetadataBLOBAsyncProvider createProvider(AuthenticatorStatus... statuses) {
        ObjectConverter objectConverter = MetadataCodecFallbackRegistrar.registerFallbackMetadataCodecsIfNeeded(new ObjectConverter());
        MetadataStatement metadataStatement = loadU2FMetadataStatement(objectConverter);
        List<StatusReport> statusReports = Arrays.stream(statuses)
                .map(status -> new StatusReport(status, null, null, null, null, null, null, null, null, null, null, null, null, null))
                .collect(Collectors.toList());
        MetadataBLOBPayloadEntry entry = new MetadataBLOBPayloadEntry(
                null,
                null,
                metadataStatement.getAttestationCertificateKeyIdentifiers(),
                metadataStatement,
                null,
                statusReports,
                LocalDate.now(),
                null,
                null);
        MetadataBLOBPayload payload = new MetadataBLOBPayload("", 0, LocalDate.now().plusDays(1), Collections.singletonList(entry));
        JWSFactory jwsFactory = new JWSFactory(objectConverter);
        JWS<MetadataBLOBPayload> jws = jwsFactory.create(new JWSHeader(JWAIdentifier.ES256, null), payload, new byte[32]);
        MetadataBLOB metadataBLOB = new MetadataBLOB(jws);
        return () -> CompletableFuture.completedFuture(metadataBLOB);
    }

    private MetadataStatement loadU2FMetadataStatement(ObjectConverter objectConverter) {
        try (InputStream inputStream = Files.newInputStream(new File("src/test/resources/com/webauthn4j/async/metadata/JsonMetadataItem_u2f.json").toPath())) {
            return objectConverter.getJsonMapper().readValue(inputStream, MetadataStatement.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
