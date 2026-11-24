/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.converter;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/**
 * Converter for {@link CollectedClientData}
 */
public class CollectedClientDataConverter {

    // Security-critical top-level members of clientDataJSON.
    // If any of these members appears more than once in the same JSON object, the document is ambiguous:
    // a JSON parser silently keeps only one of the values, so the value used for the security decision
    // and the value observed when auditing the raw document may not be the same member.
    private static final Set<String> SECURITY_CRITICAL_MEMBERS = Set.of("type", "challenge", "origin");

    //~ Instance fields
    // ================================================================================================
    private final ObjectConverter objectConverter;

    //~ Constructors
    // ================================================================================================

    public CollectedClientDataConverter(@NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.objectConverter = objectConverter;
    }

    //~ Methods
    // ================================================================================================


    /**
     * Converts from a base64url {@link String} to {@link CollectedClientData}.
     *
     * @param base64UrlString the source byte array to convert
     * @return the converted object
     */
    public @Nullable CollectedClientData convert(@NotNull String base64UrlString) {
        try {
            AssertUtil.notNull(base64UrlString, "base64UrlString must not be null");
            byte[] bytes = Base64UrlUtil.decode(base64UrlString);
            return convert(bytes);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts from a byte array to {@link CollectedClientData}.
     *
     * @param source the source byte array to convert
     * @return the converted object
     */
    public @Nullable CollectedClientData convert(@NotNull byte[] source) {
        try {
            AssertUtil.notNull(source, "source must not be null");
            String jsonString = new String(source, StandardCharsets.UTF_8);
            assertNoDuplicateSecurityCriticalMembers(jsonString);
            return objectConverter.getJsonMapper().readValue(jsonString, CollectedClientData.class);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Scans the top-level members of the clientDataJSON document and rejects it if any
     * security-critical member ({@code type}, {@code challenge} or {@code origin}) appears
     * more than once. Member names are compared after JSON escape decoding, so escaped
     * variants of the same member name are treated as the same member.
     *
     * @param jsonString the raw clientDataJSON document
     * @throws DataConversionException if a security-critical member is duplicated
     */
    private void assertNoDuplicateSecurityCriticalMembers(@NotNull String jsonString) {
        try (JsonParser parser = objectConverter.getJsonMapper().createParser(jsonString)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                // Not a JSON object; let the databind deserialization report the problem.
                return;
            }
            Set<String> seenSecurityCriticalMembers = new HashSet<>();
            while (true) {
                JsonToken token = parser.nextToken();
                if (token == null || token == JsonToken.END_OBJECT) {
                    return;
                }
                if (token != JsonToken.PROPERTY_NAME) {
                    // Unexpected structure; leave error handling to the databind deserialization.
                    return;
                }
                String memberName = parser.currentName();
                if (SECURITY_CRITICAL_MEMBERS.contains(memberName) && !seenSecurityCriticalMembers.add(memberName)) {
                    throw new DataConversionException(
                            "clientDataJSON contains a duplicate '" + memberName + "' member. " +
                                    "clientDataJSON documents with repeated type, challenge or origin members are ambiguous and rejected.");
                }
                JsonToken valueToken = parser.nextToken();
                if (valueToken != null && valueToken.isStructStart()) {
                    parser.skipChildren();
                }
            }
        } catch (JacksonException e) {
            // Malformed JSON; let the databind deserialization raise a proper DataConversionException.
        }
    }

    /**
     * Converts from a {@link CollectedClientData} to byte[].
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public @NotNull byte[] convertToBytes(@NotNull CollectedClientData source) {
        try {
            AssertUtil.notNull(source, "source must not be null");
            return objectConverter.getJsonMapper().writeValueAsBytes(source);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts from a {@link CollectedClientData} to base64 url {@link String}.
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public @NotNull String convertToBase64UrlString(@NotNull CollectedClientData source) {
        try {
            byte[] bytes = convertToBytes(source);
            return Base64UrlUtil.encodeToString(bytes);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

}
