package com.webauthn4j.credential;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class CoreCredentialRecordImplTest {

    private AttestationObject attestationObject;
    private AttestationStatement attestationStatement;
    private Boolean flagUV;
    private Boolean flagBE;
    private Boolean flagBS;
    private long signCount;
    private AttestedCredentialData attestedCredentialData;
    private AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> extensions;

    @BeforeEach
    void setUp() {
        attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = attestationObject.getAuthenticatorData();
        
        attestationStatement = attestationObject.getAttestationStatement();
        flagUV = authenticatorData.isFlagUV();
        flagBE = authenticatorData.isFlagBE();
        flagBS = authenticatorData.isFlagBS();
        signCount = authenticatorData.getSignCount();
        attestedCredentialData = authenticatorData.getAttestedCredentialData();
        extensions = authenticatorData.getExtensions();
    }

    @Test
    void shouldCreateCoreCredentialRecordWithExplicitParameters() {
        // Given

        // When
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(
                attestationStatement,
                flagUV,
                flagBE,
                flagBS,
                signCount,
                attestedCredentialData,
                extensions
        );

        // Then
        assertAll(
                () -> assertThat(coreCredentialRecord.isUvInitialized()).isEqualTo(flagUV),
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isEqualTo(flagBE),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isEqualTo(flagBS),
                () -> assertThat(coreCredentialRecord.getAttestedCredentialData()).isEqualTo(attestedCredentialData),
                () -> assertThat(coreCredentialRecord.getAttestationStatement()).isEqualTo(attestationStatement),
                () -> assertThat(coreCredentialRecord.getCounter()).isEqualTo(signCount)
        );
    }

    @Test
    void shouldCreateCoreCredentialRecordFromAttestationObject() {
        // Given

        // When
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(attestationObject);

        // Then
        assertAll(
                () -> assertThat(coreCredentialRecord.isUvInitialized()).isEqualTo(flagUV),
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isEqualTo(flagBE),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isEqualTo(flagBS),
                () -> assertThat(coreCredentialRecord.getAttestedCredentialData()).isEqualTo(attestedCredentialData),
                () -> assertThat(coreCredentialRecord.getAttestationStatement()).isEqualTo(attestationStatement),
                () -> assertThat(coreCredentialRecord.getCounter()).isEqualTo(signCount)
        );
    }

    @Test
    void shouldUpdatePropertiesViaSetters() {
        // Given
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(attestationObject);

        // When
        coreCredentialRecord.setUvInitialized(true);
        coreCredentialRecord.setBackupEligible(true);
        coreCredentialRecord.setBackedUp(true);
        coreCredentialRecord.setCounter(100);

        // Then
        assertAll(
                () -> assertThat(coreCredentialRecord.isUvInitialized()).isTrue(),
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isTrue(),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isTrue(),
                () -> assertThat(coreCredentialRecord.getCounter()).isEqualTo(100)
        );
    }

    @Test
    void shouldBeEqualWhenConstructedFromSameAttestationObject() {
        // Given
        CoreCredentialRecord instanceA = new CoreCredentialRecordImpl(attestationObject);
        CoreCredentialRecord instanceB = new CoreCredentialRecordImpl(attestationObject);

        // When
        // Then
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

    @Test
    void shouldRejectBackupStateThatContradictsBackupEligibilityOnConstruction() {
        assertThatThrownBy(() -> new CoreCredentialRecordImpl(
                attestationStatement,
                flagUV,
                false,
                true,
                signCount,
                attestedCredentialData,
                extensions
        )).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldAllowNullBackupStateForLegacyRecords() {
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(
                attestationStatement,
                null,
                null,
                null,
                signCount,
                attestedCredentialData,
                extensions
        );

        assertAll(
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isNull(),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isNull()
        );
    }

    @Test
    void shouldAllowBackupEligibleCredentialWithEitherBackupState() {
        CoreCredentialRecord backedUp = new CoreCredentialRecordImpl(
                attestationStatement, true, true, true, signCount, attestedCredentialData, extensions);
        CoreCredentialRecord notBackedUp = new CoreCredentialRecordImpl(
                attestationStatement, true, true, false, signCount, attestedCredentialData, extensions);

        assertAll(
                () -> assertThat(backedUp.isBackupEligible()).isTrue(),
                () -> assertThat(backedUp.isBackedUp()).isTrue(),
                () -> assertThat(notBackedUp.isBackupEligible()).isTrue(),
                () -> assertThat(notBackedUp.isBackedUp()).isFalse()
        );
    }

    @Test
    void shouldRejectSettingBackupEligibleFalseWhileBackedUp() {
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(
                attestationStatement, true, true, true, signCount, attestedCredentialData, extensions);

        assertThatThrownBy(() -> coreCredentialRecord.setBackupEligible(false))
                .isInstanceOf(IllegalArgumentException.class);
        assertAll(
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isTrue(),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isTrue()
        );
    }

    @Test
    void shouldRejectSettingBackedUpTrueWhileNotBackupEligible() {
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(
                attestationStatement, true, false, false, signCount, attestedCredentialData, extensions);

        assertThatThrownBy(() -> coreCredentialRecord.setBackedUp(true))
                .isInstanceOf(IllegalArgumentException.class);
        assertAll(
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isFalse(),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isFalse()
        );
    }

    @Test
    void shouldAllowClearingBackupStateBeforeClearingBackupEligibility() {
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(
                attestationStatement, true, true, true, signCount, attestedCredentialData, extensions);

        coreCredentialRecord.setBackedUp(false);
        coreCredentialRecord.setBackupEligible(false);

        assertAll(
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isFalse(),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isFalse()
        );
    }

    @Test
    void shouldAllowBackupStateWhenBackupEligibilityIsUnknown() {
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(
                attestationStatement, null, null, false, signCount, attestedCredentialData, extensions);

        coreCredentialRecord.setBackedUp(true);

        assertAll(
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isNull(),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isTrue()
        );
    }
}
