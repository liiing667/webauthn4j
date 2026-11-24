/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.metadata;

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
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataBLOBBasedMetadataStatementRepositoryTest {

    private static final byte[] U2F_KEY_IDENTIFIER = HexUtil.decode("7c0903708b87115b0b422def3138c3c864e44573");

    @TempDir
    Path tempDir;

    @Test
    void find_by_aaguid_test() throws IOException {
        AAGUID aaguid = new AAGUID("9c835346-796b-4c27-8898-d6032f515cc5");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider metadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(metadataBLOBProvider);
        assertThat(target.find(aaguid)).hasSize(1);
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_test() throws IOException {
        byte[] attestationCertificateKeyIdentifier = HexUtil.decode("31116a647069d1493f58fc5b54e5449e2a52d43e");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider metadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(metadataBLOBProvider);
        assertThat(target.find(attestationCertificateKeyIdentifier)).hasSize(1);
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_filters_notFidoCertified_entry_test() throws IOException {
        // NEOWAVE Winkeo FIDO2 (NOT_FIDO_CERTIFIED)
        byte[] attestationCertificateKeyIdentifier = HexUtil.decode("1434d2f277fe479c35ddf6aa4d08a07cbce99dd7");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider metadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(metadataBLOBProvider);
        assertThat(target.find(attestationCertificateKeyIdentifier)).isEmpty();
        target.setNotFidoCertifiedAllowed(true);
        assertThat(target.find(attestationCertificateKeyIdentifier)).hasSize(1);
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_filters_mixed_status_entry_test() throws IOException {
        // TrustKey G320 U2F Authenticator (FIDO_CERTIFIED_L1 and NOT_FIDO_CERTIFIED)
        byte[] attestationCertificateKeyIdentifier = HexUtil.decode("32526f73dfca12da9c1d87d6e0adb64e843f73da");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider metadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(metadataBLOBProvider);
        assertThat(target.find(attestationCertificateKeyIdentifier)).isEmpty();
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_filters_revoked_entry_test() {
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(createProvider(AuthenticatorStatus.REVOKED));
        assertThat(target.find(U2F_KEY_IDENTIFIER)).isEmpty();
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_filters_attestation_key_compromise_entry_test() {
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(createProvider(AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE));
        assertThat(target.find(U2F_KEY_IDENTIFIER)).isEmpty();
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_filters_mixed_status_reports_test() {
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(createProvider(AuthenticatorStatus.FIDO_CERTIFIED, AuthenticatorStatus.REVOKED));
        assertThat(target.find(U2F_KEY_IDENTIFIER)).isEmpty();
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_fails_closed_on_conflicting_sources_test() {
        MetadataBLOBProvider revokedProvider = createProvider(AuthenticatorStatus.REVOKED);
        MetadataBLOBProvider certifiedProvider = createProvider(AuthenticatorStatus.FIDO_CERTIFIED);
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(revokedProvider, certifiedProvider);
        assertThat(target.find(U2F_KEY_IDENTIFIER)).isEmpty();
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_returns_certified_entry_test() {
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(createProvider(AuthenticatorStatus.FIDO_CERTIFIED));
        assertThat(target.find(U2F_KEY_IDENTIFIER)).hasSize(1);
    }

    @Test
    void notFidoCertifiedAllowed_test() throws IOException {
        AAGUID aaguid = new AAGUID("3789da91-f943-46bc-95c3-50ea2012f03a");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider metadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(metadataBLOBProvider);
        target.setNotFidoCertifiedAllowed(false);
        assertThat(target.isNotFidoCertifiedAllowed()).isFalse();
        assertThat(target.find(aaguid)).isEmpty();
        target.setNotFidoCertifiedAllowed(true);
        assertThat(target.find(aaguid)).hasSize(1);
        assertThat(target.isNotFidoCertifiedAllowed()).isTrue();
    }

    @Test
    void selfAssertionSubmittedAllowed_test() throws IOException {
        AAGUID aaguid = new AAGUID("01d993d9-33d7-4db5-a7a9-7edc56ddfdb5");
        Path blobPath = new File("src/test/resources/integration/component/test-blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider metadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(metadataBLOBProvider);

        target.setSelfAssertionSubmittedAllowed(false);
        assertThat(target.isSelfAssertionSubmittedAllowed()).isFalse();
        assertThat(target.find(aaguid)).isEmpty();

        target.setSelfAssertionSubmittedAllowed(true);
        assertThat(target.find(aaguid)).hasSize(1);
        assertThat(target.isSelfAssertionSubmittedAllowed()).isTrue();
    }

    private MetadataBLOBProvider createProvider(AuthenticatorStatus... statuses) {
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
        return () -> metadataBLOB;
    }

    private MetadataStatement loadU2FMetadataStatement(ObjectConverter objectConverter) {
        try (InputStream inputStream = Files.newInputStream(new File("src/test/resources/com/webauthn4j/metadata/JsonMetadataItem_u2f.json").toPath())) {
            return objectConverter.getJsonMapper().readValue(inputStream, MetadataStatement.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
