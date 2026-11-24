package com.webauthn4j.async.metadata;

import com.webauthn4j.metadata.exception.MDSException;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;

public class SimpleHttpAsyncClient implements HttpAsyncClient {
    @Override
    public @NotNull CompletionStage<com.webauthn4j.metadata.HttpClient.Response> fetch(@NotNull String uri) throws MDSException {
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .timeout(Duration.ofSeconds(60))
                .build();
        return client.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream())
                .thenApply(response -> {
                    if(response.statusCode() != HttpURLConnection.HTTP_OK){
                        closeQuietly(response.body());
                        throw new MDSException("failed to fetch " + uri + " (HTTP status " + response.statusCode() + ")");
                    }
                    return new com.webauthn4j.metadata.HttpClient.Response(response.statusCode(), response.body());
                })
                .exceptionally(e -> {
                    Throwable cause = e instanceof CompletionException && e.getCause() != null ? e.getCause() : e;
                    if (cause instanceof MDSException) {
                        throw (MDSException) cause;
                    }
                    throw new MDSException(cause);
                });
    }

    private static void closeQuietly(InputStream inputStream) {
        try {
            inputStream.close();
        }
        catch (IOException ignored) {
            // The response is rejected regardless of whether the body can be closed.
        }
    }
}
