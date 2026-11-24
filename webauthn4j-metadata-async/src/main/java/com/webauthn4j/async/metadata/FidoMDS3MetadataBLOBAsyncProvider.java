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

package com.webauthn4j.async.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.CertPathCheckContext;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBFactory;
import com.webauthn4j.metadata.exception.CertPathCheckException;
import com.webauthn4j.metadata.exception.MDSException;
import com.webauthn4j.metadata.util.internal.DefaultCertPathChecker;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertPath;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Load MetadataBLOB from the FIDO Alliance Metadata Service. This provider validates MetadataBLOB signature.
 */
public class FidoMDS3MetadataBLOBAsyncProvider extends CachingMetadataBLOBAsyncProvider {

    public static final String DEFAULT_BLOB_ENDPOINT = "https://mds.fidoalliance.org/";
    /**
     * Default upper bound of a MetadataBLOB response body.
     * The bound prevents an unexpected or malicious response from being read into memory without limit.
     */
    public static final int DEFAULT_MAX_RESPONSE_BODY_SIZE = 10 * 1024 * 1024;

    private static final Executor DEFAULT_CERT_PATH_VALIDATION_EXECUTOR =
            Executors.newSingleThreadExecutor(runnable -> {
                Thread thread = new Thread(runnable, "webauthn4j-mds-cert-path-validation");
                thread.setDaemon(true);
                return thread;
            });

    private final MetadataBLOBFactory metadataBLOBFactory;
    private final String blobEndpoint;
    private final HttpAsyncClient httpClient;
    private final Set<TrustAnchor> trustAnchors;
    private boolean revocationCheckEnabled = true;
    private int maxResponseBodySize = DEFAULT_MAX_RESPONSE_BODY_SIZE;
    private CertPathAsyncChecker certPathAsyncChecker;

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull HttpAsyncClient httpClient, @NotNull Set<TrustAnchor> trustAnchors, @NotNull Executor certPathValidationExecutor) {
        this.metadataBLOBFactory = new MetadataBLOBFactory(objectConverter);
        this.blobEndpoint = blobEndpoint;
        this.httpClient = httpClient;
        this.trustAnchors = trustAnchors;
        this.certPathAsyncChecker = new DefaultCertPathAsyncChecker(certPathValidationExecutor);
    }

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull HttpAsyncClient httpClient, @NotNull Set<TrustAnchor> trustAnchors) {
        this(objectConverter, blobEndpoint, httpClient, trustAnchors, DEFAULT_CERT_PATH_VALIDATION_EXECUTOR);
    }

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull Set<TrustAnchor> trustAnchors) {
        this(objectConverter, blobEndpoint, new SimpleHttpAsyncClient(), trustAnchors);
    }

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull String blobEndpoint, @NotNull X509Certificate trustAnchorCertificate) {
        this(objectConverter, blobEndpoint, new SimpleHttpAsyncClient(), Collections.singleton(new TrustAnchor(trustAnchorCertificate, null)));
    }

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull Set<TrustAnchor> trustAnchors) {
        this(objectConverter, DEFAULT_BLOB_ENDPOINT, trustAnchors);
    }

    public FidoMDS3MetadataBLOBAsyncProvider(@NotNull ObjectConverter objectConverter, @NotNull X509Certificate trustAnchorCertificate) {
        this(objectConverter, DEFAULT_BLOB_ENDPOINT, Collections.singleton(new TrustAnchor(trustAnchorCertificate, null)));
    }

    @Override
    protected @NotNull CompletionStage<MetadataBLOB> doProvide() {
        return httpClient.fetch(blobEndpoint).thenApply(response -> {
            assertSuccessfulResponse(response);
            String body = readAsString(response.getBody());
            MetadataBLOB metadataBLOB;
            try {
                metadataBLOB = metadataBLOBFactory.parse(body);
            }
            catch (RuntimeException e) {
                throw new MDSException("Failed to parse response as MetadataBLOB", e);
            }
            validateFreshness(metadataBLOB);
            return metadataBLOB;
        }).thenCompose(metadataBLOB -> {
            if(!metadataBLOB.isValidSignature()){
                throw new MDSException("MetadataBLOB signature is invalid");
            }
            return validateCertPath(metadataBLOB).thenApply(unused -> metadataBLOB);
        });
    }

    private void assertSuccessfulResponse(@NotNull com.webauthn4j.metadata.HttpClient.Response response) {
        if(response == null){
            throw new MDSException("MetadataBLOB endpoint returned no response");
        }
        if(response.getStatusCode() != HttpURLConnection.HTTP_OK){
            closeQuietly(response.getBody());
            throw new MDSException("MetadataBLOB endpoint returned HTTP status " + response.getStatusCode());
        }
    }

    private @NotNull String readAsString(@NotNull InputStream responseBody) {
        if(responseBody == null){
            throw new MDSException("MetadataBLOB response body is missing");
        }
        try (InputStream body = responseBody) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            long total = 0;
            while (true) {
                int maxRead = (int) Math.min(buffer.length, (long) maxResponseBodySize - total + 1);
                int read = body.read(buffer, 0, maxRead);
                if (read == -1) {
                    break;
                }
                total += read;
                if (total > maxResponseBodySize) {
                    throw new MDSException("MetadataBLOB response body exceeds the maximum size of " + maxResponseBodySize + " bytes");
                }
                outputStream.write(buffer, 0, read);
            }
            return new String(outputStream.toByteArray(), StandardCharsets.UTF_8);
        }
        catch (IOException e) {
            throw new MDSException("Failed to read response body", e);
        }
    }

    private void validateFreshness(@NotNull MetadataBLOB metadataBLOB) {
        LocalDate nextUpdate = metadataBLOB.getPayload().getNextUpdate();
        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        if (nextUpdate == null || !nextUpdate.isAfter(today)) {
            throw new MDSException("MetadataBLOB is expired: nextUpdate=" + nextUpdate + ", today=" + today);
        }
    }

    private static void closeQuietly(InputStream inputStream) {
        if (inputStream != null) {
            try {
                inputStream.close();
            }
            catch (IOException ignored) {
                // The response is rejected regardless of whether the body can be closed.
            }
        }
    }

    private CompletionStage<Void> validateCertPath(@NotNull MetadataBLOB metadataBLOB) {
        CertPath certPath = metadataBLOB.getHeader().getX5c();
        try{
            return certPathAsyncChecker.check(new CertPathCheckContext(certPath, trustAnchors, isRevocationCheckEnabled()));
        }
        catch (CertPathCheckException e){
            throw new MDSException("MetadataBLOB certificate chain validation failed", e);
        }
    }

    public boolean isRevocationCheckEnabled() {
        return revocationCheckEnabled;
    }

    public void setRevocationCheckEnabled(boolean revocationCheckEnabled) {
        this.revocationCheckEnabled = revocationCheckEnabled;
    }

    public CertPathAsyncChecker getCertPathAsyncValidator() {
        return certPathAsyncChecker;
    }

    public void setCertPathAsyncValidator(CertPathAsyncChecker certPathAsyncChecker) {
        this.certPathAsyncChecker = certPathAsyncChecker;
    }

    public int getMaxResponseBodySize() {
        return maxResponseBodySize;
    }

    public void setMaxResponseBodySize(int maxResponseBodySize) {
        if (maxResponseBodySize <= 0) {
            throw new IllegalArgumentException("maxResponseBodySize must be greater than zero");
        }
        this.maxResponseBodySize = maxResponseBodySize;
    }

    private static class DefaultCertPathAsyncChecker implements CertPathAsyncChecker {

        private final Executor executor;
        private final DefaultCertPathChecker delegate = new DefaultCertPathChecker();

        public DefaultCertPathAsyncChecker(Executor executor){
            this.executor = executor;
        }

        @Override
        public CompletionStage<Void> check(CertPathCheckContext context) throws MDSException {
            return CompletableFuture.completedStage(null)
                    .thenCompose(unused -> CompletableFuture.runAsync(() -> delegate.check(context), executor));
        }
    }
}
