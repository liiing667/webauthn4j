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

package com.webauthn4j.appattest;

import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import com.webauthn4j.appattest.data.DCAssertionParameters;
import com.webauthn4j.appattest.data.DCAssertionRequest;
import com.webauthn4j.appattest.server.DCServerProperty;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.HexUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.verifier.CustomCoreAuthenticationVerifier;
import com.webauthn4j.verifier.exception.BadSignatureException;
import com.webauthn4j.verifier.exception.MaliciousCounterValueException;
import com.webauthn4j.verifier.exception.VerificationException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifies that assertion acceptance and the device counter update are published atomically:
 * an assertion that is rejected, replayed or tampered with must never consume the counter
 * of the next valid assertion, while a normal first assertion must keep working.
 */
class DeviceCheckAssertionTransactionTest {

    private static final String APP_IDENTIFIER = "K38V9TR83U.com.example.webauthn4j.appattest.debug";
    private static final byte[] APPLE_EXTENSIONS = HexUtil.decode("A2776170706C655F62756E646C655F76657273696F6E5F30316131781C6170706C655F76616C69646174696F6E5F63617465676F72795F30314403000000");

    private final byte[] challenge = "transaction_test_challenge".getBytes(StandardCharsets.UTF_8);
    private final byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(challenge);

    @Test
    void first_assertion_is_accepted_and_counter_is_published_test() {
        KeyPair keyPair = ECUtil.createKeyPair();
        byte[] keyId = keyId("first");
        DCAppleDevice device = TestDataUtil.createAppAttestDevice(keyPair, keyId);
        DCAssertionRequest request = request(keyPair, keyId, 1);

        assertThatCode(() -> manager().verify(request, parameters(device))).doesNotThrowAnyException();
        assertThat(device.getCounter()).isEqualTo(1);
    }

    @Test
    void business_policy_rejection_does_not_consume_counter_test() {
        KeyPair keyPair = ECUtil.createKeyPair();
        byte[] keyId = keyId("rejection");
        DCAppleDevice device = TestDataUtil.createAppAttestDevice(keyPair, keyId);
        DCAssertionRequest request = request(keyPair, keyId, 1);

        // The assertion passes signature verification, but the Relying Party policy rejects it.
        DeviceCheckAssertionManager rejectingManager = manager(authenticationObject -> {
            throw new PolicyViolationException("rejected by business policy");
        });
        assertThatThrownBy(() -> rejectingManager.verify(request, parameters(device)))
                .isInstanceOf(PolicyViolationException.class);

        // The device counter must not have been advanced...
        assertThat(device.getCounter()).isZero();

        // ...so a retry keeping the original state is still accepted.
        assertThatCode(() -> manager().verify(request, parameters(device))).doesNotThrowAnyException();
        assertThat(device.getCounter()).isEqualTo(1);
    }

    @Test
    void replay_does_not_consume_next_valid_assertion_test() {
        KeyPair keyPair = ECUtil.createKeyPair();
        byte[] keyId = keyId("replay");
        DCAppleDevice device = TestDataUtil.createAppAttestDevice(keyPair, keyId);
        DeviceCheckAssertionManager manager = manager();

        DCAssertionRequest firstRequest = request(keyPair, keyId, 1);
        manager.verify(firstRequest, parameters(device));
        assertThat(device.getCounter()).isEqualTo(1);

        // Replaying the consumed assertion is rejected and must not move the counter.
        assertThatThrownBy(() -> manager.verify(firstRequest, parameters(device)))
                .isInstanceOf(MaliciousCounterValueException.class);
        assertThat(device.getCounter()).isEqualTo(1);

        // The next valid assertion is still accepted.
        DCAssertionRequest nextRequest = request(keyPair, keyId, 2);
        assertThatCode(() -> manager.verify(nextRequest, parameters(device))).doesNotThrowAnyException();
        assertThat(device.getCounter()).isEqualTo(2);
    }

    @Test
    void tampered_extensions_do_not_consume_counter_test() {
        KeyPair keyPair = ECUtil.createKeyPair();
        byte[] keyId = keyId("tampered");
        DCAppleDevice device = TestDataUtil.createAppAttestDevice(keyPair, keyId);
        DeviceCheckAssertionManager manager = manager();

        byte[] signedAuthenticatorData = TestDataUtil.createAppAttestAssertionAuthenticatorData(APP_IDENTIFIER, 1, APPLE_EXTENSIONS);
        byte[] tamperedAuthenticatorData = signedAuthenticatorData.clone();
        tamperedAuthenticatorData[tamperedAuthenticatorData.length - 4] = 0x02;
        byte[] tamperedAssertion = TestDataUtil.createAppAttestAssertion(keyPair, signedAuthenticatorData, clientDataHash, tamperedAuthenticatorData);

        assertThatThrownBy(() -> manager.verify(new DCAssertionRequest(keyId, tamperedAssertion, clientDataHash), parameters(device)))
                .isInstanceOf(BadSignatureException.class);
        assertThat(device.getCounter()).isZero();

        // The valid assertion the tampered one tried to preempt is still accepted.
        assertThatCode(() -> manager.verify(request(keyPair, keyId, 1), parameters(device))).doesNotThrowAnyException();
        assertThat(device.getCounter()).isEqualTo(1);
    }

    @Test
    void assertion_from_another_keyId_does_not_pollute_device_test() {
        KeyPair keyPair = ECUtil.createKeyPair();
        byte[] keyId = keyId("victim");
        DCAppleDevice device = TestDataUtil.createAppAttestDevice(keyPair, keyId);
        DeviceCheckAssertionManager manager = manager();

        // An assertion produced by a different key (another keyId) with a far ahead counter.
        KeyPair otherKeyPair = ECUtil.createKeyPair();
        byte[] otherKeyId = keyId("other");
        DCAssertionRequest foreignRequest = request(otherKeyPair, otherKeyId, 100);

        assertThatThrownBy(() -> manager.verify(foreignRequest, parameters(device)))
                .isInstanceOf(BadSignatureException.class);
        assertThat(device.getCounter()).isZero();

        // The device's own next valid assertion is still accepted.
        assertThatCode(() -> manager.verify(request(keyPair, keyId, 1), parameters(device))).doesNotThrowAnyException();
        assertThat(device.getCounter()).isEqualTo(1);
    }

    private DeviceCheckAssertionManager manager(CustomCoreAuthenticationVerifier... customVerifiers) {
        List<CustomCoreAuthenticationVerifier> verifiers = customVerifiers.length == 0
                ? Collections.emptyList()
                : List.of(customVerifiers);
        return new DeviceCheckAssertionManager(verifiers);
    }

    private DCAssertionRequest request(KeyPair keyPair, byte[] keyId, long counter) {
        byte[] authenticatorData = TestDataUtil.createAppAttestAssertionAuthenticatorData(APP_IDENTIFIER, counter, APPLE_EXTENSIONS);
        byte[] assertion = TestDataUtil.createAppAttestAssertion(keyPair, authenticatorData, clientDataHash);
        return new DCAssertionRequest(keyId, assertion, clientDataHash);
    }

    private DCAssertionParameters parameters(DCAppleDevice device) {
        return new DCAssertionParameters(new DCServerProperty(APP_IDENTIFIER, new DefaultChallenge(challenge)), device);
    }

    private static byte[] keyId(String seed) {
        return MessageDigestUtil.createSHA256().digest(seed.getBytes(StandardCharsets.UTF_8));
    }

    private static class PolicyViolationException extends VerificationException {
        PolicyViolationException(String message) {
            super(message);
        }
    }
}
