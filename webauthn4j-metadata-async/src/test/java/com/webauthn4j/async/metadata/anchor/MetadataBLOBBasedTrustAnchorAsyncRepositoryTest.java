package com.webauthn4j.async.metadata.anchor;

import com.webauthn4j.async.metadata.LocalFileMetadataBLOBAsyncProvider;
import com.webauthn4j.async.metadata.MetadataBLOBAsyncProvider;
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
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.HexUtil;
import com.webauthn4j.verifier.RegistrationObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataBLOBBasedTrustAnchorAsyncRepositoryTest {

    private static final byte[] U2F_KEY_IDENTIFIER = HexUtil.decode("7c0903708b87115b0b422def3138c3c864e44573");

    @TempDir
    Path tempDir;

    @Test
    void find_by_aaguid_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedTrustAnchorAsyncRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        Set<TrustAnchor> trustAnchors = target.find(new AAGUID("08987058-CADC-4B81-B6E1-30DE50DCBE96")).toCompletableFuture().get();
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedTrustAnchorAsyncRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        Set<TrustAnchor> trustAnchors = target.find(HexUtil.decode("31116a647069d1493f58fc5b54e5449e2a52d43e")).toCompletableFuture().get();
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_filters_revoked_entry_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedTrustAnchorAsyncRepository target = new MetadataBLOBBasedTrustAnchorAsyncRepository(createProvider(AuthenticatorStatus.REVOKED));
        assertThat(target.find(U2F_KEY_IDENTIFIER).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_filters_attestation_key_compromise_entry_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedTrustAnchorAsyncRepository target = new MetadataBLOBBasedTrustAnchorAsyncRepository(createProvider(AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE));
        assertThat(target.find(U2F_KEY_IDENTIFIER).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_filters_mixed_status_reports_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedTrustAnchorAsyncRepository target = new MetadataBLOBBasedTrustAnchorAsyncRepository(createProvider(AuthenticatorStatus.FIDO_CERTIFIED, AuthenticatorStatus.REVOKED));
        assertThat(target.find(U2F_KEY_IDENTIFIER).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_fails_closed_on_conflicting_sources_test() throws ExecutionException, InterruptedException {
        MetadataBLOBAsyncProvider revokedProvider = createProvider(AuthenticatorStatus.REVOKED);
        MetadataBLOBAsyncProvider certifiedProvider = createProvider(AuthenticatorStatus.FIDO_CERTIFIED);
        MetadataBLOBBasedTrustAnchorAsyncRepository target = new MetadataBLOBBasedTrustAnchorAsyncRepository(revokedProvider, certifiedProvider);
        assertThat(target.find(U2F_KEY_IDENTIFIER).toCompletableFuture().get()).isEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_returns_certified_entry_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedTrustAnchorAsyncRepository target = new MetadataBLOBBasedTrustAnchorAsyncRepository(createProvider(AuthenticatorStatus.FIDO_CERTIFIED));
        assertThat(target.find(U2F_KEY_IDENTIFIER).toCompletableFuture().get()).isNotEmpty();
    }

    @Test
    void validate_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedTrustAnchorAsyncRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        @SuppressWarnings("ConstantConditions")
        AAGUID aaguid = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid();
        assertThat(target.find(aaguid).toCompletableFuture().get()).isNotEmpty();
    }

    @Test
    void setNotFidoCertifiedAllowed_test() throws ExecutionException, InterruptedException {
        Set<TrustAnchor> trustAnchors;

        MetadataBLOBBasedTrustAnchorAsyncRepository target = createWithBlob("src/test/resources/integration/component/test-blob.jwt");

        target.setNotFidoCertifiedAllowed(false);
        trustAnchors = target.find(new AAGUID("d54e9697-08ca-4d95-b2c2-ef9dd7c7d105")).toCompletableFuture().get();
        assertThat(trustAnchors).isEmpty();
        assertThat(target.isNotFidoCertifiedAllowed()).isFalse();

        target.setNotFidoCertifiedAllowed(true);
        trustAnchors = target.find(new AAGUID("d54e9697-08ca-4d95-b2c2-ef9dd7c7d105")).toCompletableFuture().get();
        assertThat(trustAnchors).isNotEmpty();
        assertThat(target.isNotFidoCertifiedAllowed()).isTrue();
    }

    @Test
    void setSelfAssertionSubmittedAllowed_test() throws ExecutionException, InterruptedException {
        Set<TrustAnchor> trustAnchors;

        MetadataBLOBBasedTrustAnchorAsyncRepository target = createWithBlob("src/test/resources/integration/component/test-blob.jwt");

        target.setSelfAssertionSubmittedAllowed(false);
        trustAnchors = target.find(new AAGUID("60a94677-44e9-4594-a94e-cf44effd8b9a")).toCompletableFuture().get();
        assertThat(trustAnchors).isEmpty();
        assertThat(target.isSelfAssertionSubmittedAllowed()).isFalse();

        target.setSelfAssertionSubmittedAllowed(true);
        trustAnchors = target.find(new AAGUID("60a94677-44e9-4594-a94e-cf44effd8b9a")).toCompletableFuture().get();
        assertThat(trustAnchors).isNotEmpty();
        assertThat(target.isSelfAssertionSubmittedAllowed()).isTrue();
    }

    private MetadataBLOBBasedTrustAnchorAsyncRepository createWithBlob(String filePath){
        try {
            Path blobPath = new File(filePath).toPath();
            Path dstPath = tempDir.resolve("blob.jwt");
            Files.copy(blobPath, dstPath);
            LocalFileMetadataBLOBAsyncProvider localFileMetadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
            return new MetadataBLOBBasedTrustAnchorAsyncRepository(localFileMetadataBLOBAsyncProvider);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
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
