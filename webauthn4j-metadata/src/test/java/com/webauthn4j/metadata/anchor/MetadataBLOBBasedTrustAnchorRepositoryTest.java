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

package com.webauthn4j.metadata.anchor;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.metadata.LocalFileMetadataBLOBProvider;
import com.webauthn4j.metadata.MetadataBLOBProvider;
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
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataBLOBBasedTrustAnchorRepositoryTest {

    private static final byte[] U2F_KEY_IDENTIFIER = HexUtil.decode("7c0903708b87115b0b422def3138c3c864e44573");

    @TempDir
    Path tempDir;

    @Test
    void find_by_aaguid_test(){
        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        Set<TrustAnchor> trustAnchors = target.find(new AAGUID("08987058-CADC-4B81-B6E1-30DE50DCBE96"));
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_test(){
        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        Set<TrustAnchor> trustAnchors = target.find(HexUtil.decode("31116a647069d1493f58fc5b54e5449e2a52d43e"));
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_filters_notFidoCertified_entry_test(){
        // NEOWAVE Badgeo FIDO2 (NOT_FIDO_CERTIFIED)
        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        assertThat(target.find(HexUtil.decode("2fea8f357c7a54a57f45cda72fafb34d1d449fd4"))).isEmpty();
        target.setNotFidoCertifiedAllowed(true);
        assertThat(target.find(HexUtil.decode("2fea8f357c7a54a57f45cda72fafb34d1d449fd4"))).isNotEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_filters_mixed_status_entry_test(){
        // TrustKey G320 U2F Authenticator (FIDO_CERTIFIED_L1 and NOT_FIDO_CERTIFIED)
        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        assertThat(target.find(HexUtil.decode("32526f73dfca12da9c1d87d6e0adb64e843f73da"))).isEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_filters_revoked_entry_test(){
        MetadataBLOBBasedTrustAnchorRepository target = new MetadataBLOBBasedTrustAnchorRepository(createProvider(AuthenticatorStatus.REVOKED));
        assertThat(target.find(U2F_KEY_IDENTIFIER)).isEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_filters_attestation_key_compromise_entry_test(){
        MetadataBLOBBasedTrustAnchorRepository target = new MetadataBLOBBasedTrustAnchorRepository(createProvider(AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE));
        assertThat(target.find(U2F_KEY_IDENTIFIER)).isEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_fails_closed_on_conflicting_sources_test(){
        MetadataBLOBProvider revokedProvider = createProvider(AuthenticatorStatus.REVOKED);
        MetadataBLOBProvider certifiedProvider = createProvider(AuthenticatorStatus.FIDO_CERTIFIED);
        MetadataBLOBBasedTrustAnchorRepository target = new MetadataBLOBBasedTrustAnchorRepository(revokedProvider, certifiedProvider);
        assertThat(target.find(U2F_KEY_IDENTIFIER)).isEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_returns_certified_entry_test(){
        MetadataBLOBBasedTrustAnchorRepository target = new MetadataBLOBBasedTrustAnchorRepository(createProvider(AuthenticatorStatus.FIDO_CERTIFIED));
        assertThat(target.find(U2F_KEY_IDENTIFIER)).isNotEmpty();
    }

    @Test
    void find_by_aaguid_and_attestationCertificateIdentifier_reach_same_conclusion_test(){
        // NEOWAVE Winkeo FIDO2 is listed both by AAGUID and by attestation certificate key identifier
        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        AAGUID aaguid = new AAGUID("3789da91-f943-46bc-95c3-50ea2012f03a");
        byte[] keyIdentifier = HexUtil.decode("1434d2f277fe479c35ddf6aa4d08a07cbce99dd7");

        assertThat(target.find(aaguid)).isEmpty();
        assertThat(target.find(keyIdentifier)).isEmpty();

        target.setNotFidoCertifiedAllowed(true);
        assertThat(target.find(aaguid)).isNotEmpty();
        assertThat(target.find(keyIdentifier)).isNotEmpty();
    }

    @Test
    void validate_test() {
        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        @SuppressWarnings("ConstantConditions")
        AAGUID aaguid = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid();
        assertThat(target.find(aaguid)).isNotEmpty();
    }

    @Test
    void setNotFidoCertifiedAllowed_test(){
        Set<TrustAnchor> trustAnchors;

        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/test-blob.jwt");

        target.setNotFidoCertifiedAllowed(false);
        trustAnchors = target.find(new AAGUID("d54e9697-08ca-4d95-b2c2-ef9dd7c7d105"));
        assertThat(trustAnchors).isEmpty();
        assertThat(target.isNotFidoCertifiedAllowed()).isFalse();

        target.setNotFidoCertifiedAllowed(true);
        trustAnchors = target.find(new AAGUID("d54e9697-08ca-4d95-b2c2-ef9dd7c7d105"));
        assertThat(trustAnchors).isNotEmpty();
        assertThat(target.isNotFidoCertifiedAllowed()).isTrue();
    }

    @Test
    void setSelfAssertionSubmittedAllowed_test(){
        Set<TrustAnchor> trustAnchors;

        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/test-blob.jwt");

        target.setSelfAssertionSubmittedAllowed(false);
        trustAnchors = target.find(new AAGUID("60a94677-44e9-4594-a94e-cf44effd8b9a"));
        assertThat(trustAnchors).isEmpty();
        assertThat(target.isSelfAssertionSubmittedAllowed()).isFalse();

        target.setSelfAssertionSubmittedAllowed(true);
        trustAnchors = target.find(new AAGUID("60a94677-44e9-4594-a94e-cf44effd8b9a"));
        assertThat(trustAnchors).isNotEmpty();
        assertThat(target.isSelfAssertionSubmittedAllowed()).isTrue();
    }

    private MetadataBLOBBasedTrustAnchorRepository createWithBlob(String filePath){
        try {
            Path blobPath = new File(filePath).toPath();
            Path dstPath = tempDir.resolve("blob.jwt");
            Files.copy(blobPath, dstPath);
            LocalFileMetadataBLOBProvider localFileMetadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
            return new MetadataBLOBBasedTrustAnchorRepository(localFileMetadataBLOBProvider);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
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
