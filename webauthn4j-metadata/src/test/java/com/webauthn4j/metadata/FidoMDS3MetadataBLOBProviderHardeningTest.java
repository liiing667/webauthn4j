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
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.exception.MDSException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FidoMDS3MetadataBLOBProviderHardeningTest {

    private static final String ENDPOINT = "https://mds.example.test/";

    @Test
    void non_200_response_is_rejected_without_reading_body_and_retry_refetches() {
        AtomicInteger fetchCount = new AtomicInteger();
        AtomicInteger bodyReadCount = new AtomicInteger();
        HttpClient httpClient = url -> {
            fetchCount.incrementAndGet();
            return new HttpClient.Response(503, new InputStream() {
                @Override
                public int read() {
                    bodyReadCount.incrementAndGet();
                    throw new AssertionError("the error response body must not be read");
                }
            });
        };
        FidoMDS3MetadataBLOBProvider target = provider(httpClient);

        assertThatThrownBy(target::provide).isInstanceOf(MDSException.class);
        assertThatThrownBy(target::provide).isInstanceOf(MDSException.class);

        assertThat(bodyReadCount).hasValue(0);
        assertThat(fetchCount).hasValue(2);
    }

    @Test
    void expired_blob_is_rejected_and_retry_refetches() throws IOException, URISyntaxException {
        Path blobJwtPath = Paths.get(ClassLoader.getSystemResource("integration/component/blob.jwt").toURI());
        byte[] expiredBlob = Files.readAllBytes(blobJwtPath);
        AtomicInteger fetchCount = new AtomicInteger();
        HttpClient httpClient = url -> {
            fetchCount.incrementAndGet();
            return new HttpClient.Response(200, new ByteArrayInputStream(expiredBlob));
        };
        FidoMDS3MetadataBLOBProvider target = provider(httpClient);

        assertThatThrownBy(target::provide)
                .isInstanceOf(MDSException.class)
                .hasMessageContaining("expired");
        assertThatThrownBy(target::provide)
                .isInstanceOf(MDSException.class)
                .hasMessageContaining("expired");

        assertThat(fetchCount).hasValue(2);
    }

    @Test
    void oversized_response_is_rejected_and_retry_refetches() {
        byte[] body = new byte[1024 * 1024];
        AtomicInteger fetchCount = new AtomicInteger();
        AtomicInteger readBytes = new AtomicInteger();
        HttpClient httpClient = url -> {
            fetchCount.incrementAndGet();
            return new HttpClient.Response(200, new InputStream() {
                private int position;

                @Override
                public int read() {
                    if (position >= body.length) {
                        return -1;
                    }
                    readBytes.incrementAndGet();
                    return body[position++];
                }

                @Override
                public int read(byte[] buffer, int offset, int length) {
                    if (position >= body.length) {
                        return -1;
                    }
                    int read = Math.min(length, body.length - position);
                    System.arraycopy(body, position, buffer, offset, read);
                    position += read;
                    readBytes.addAndGet(read);
                    return read;
                }
            });
        };
        FidoMDS3MetadataBLOBProvider target = provider(httpClient);
        target.setMaxResponseBodySize(1024);

        assertThatThrownBy(target::provide)
                .isInstanceOf(MDSException.class)
                .hasMessageContaining("maximum size");
        assertThatThrownBy(target::provide)
                .isInstanceOf(MDSException.class)
                .hasMessageContaining("maximum size");

        assertThat(fetchCount).hasValue(2);
        assertThat(readBytes.get()).isLessThan(body.length);
    }

    @Test
    void successful_response_after_failure_is_published_and_cached() throws IOException, URISyntaxException {
        Path blobJwtPath = Paths.get(ClassLoader.getSystemResource("integration/component/fresh-blob.jwt").toURI());
        byte[] freshBlob = Files.readAllBytes(blobJwtPath);
        AtomicInteger fetchCount = new AtomicInteger();
        HttpClient httpClient = url -> {
            if (fetchCount.incrementAndGet() == 1) {
                return new HttpClient.Response(503, new ByteArrayInputStream(new byte[0]));
            }
            return new HttpClient.Response(200, new ByteArrayInputStream(freshBlob));
        };
        FidoMDS3MetadataBLOBProvider target = provider(httpClient);

        assertThatThrownBy(target::provide).isInstanceOf(MDSException.class);
        MetadataBLOB metadataBLOB = target.provide();
        MetadataBLOB cachedMetadataBLOB = target.provide();

        assertThat(cachedMetadataBLOB).isSameAs(metadataBLOB);
        assertThat(fetchCount).hasValue(2);
    }

    private static FidoMDS3MetadataBLOBProvider provider(HttpClient httpClient) {
        FidoMDS3MetadataBLOBProvider target = new FidoMDS3MetadataBLOBProvider(
                new ObjectConverter(), ENDPOINT, httpClient, Collections.emptySet());
        target.setCertPathChecker(context -> {
            // The response checks under test happen before certificate path validation.
        });
        return target;
    }
}
