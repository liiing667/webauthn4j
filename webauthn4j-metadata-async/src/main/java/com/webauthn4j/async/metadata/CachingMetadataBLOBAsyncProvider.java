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

import com.webauthn4j.metadata.data.MetadataBLOB;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicReference;

public abstract class CachingMetadataBLOBAsyncProvider implements MetadataBLOBAsyncProvider {

    private final Clock clock;
    // CacheState is an immutable snapshot published by replacing the reference.
    @SuppressWarnings("java:S3077")
    private volatile CacheState cache = null;
    private final AtomicReference<CompletableFuture<MetadataBLOB>> inFlight = new AtomicReference<>();

    public CachingMetadataBLOBAsyncProvider() {
        this(Clock.system(ZoneOffset.UTC));
    }

    CachingMetadataBLOBAsyncProvider(@NotNull Clock clock) {
        this.clock = clock;
    }

    @Override
    public @NotNull CompletionStage<MetadataBLOB> provide(){

        CacheState current = cache;
        if(!needsMetadataBLOBUpdate(current, clock)){
            return CompletableFuture.completedFuture(current.blob);
        }

        while(true) {
            CompletableFuture<MetadataBLOB> existing = inFlight.get();
            if (existing != null) {
                return existing;
            }

            CompletableFuture<MetadataBLOB> future = new CompletableFuture<>();
            if (inFlight.compareAndSet(null, future)) {
                CompletionStage<MetadataBLOB> stage;
                try {
                    stage = doProvide();
                }
                catch (Throwable e) {
                    inFlight.compareAndSet(future, null);
                    completeExceptionallyOrWithPrevious(future, e);
                    return future;
                }
                stage.whenComplete((metadataBLOB, e) -> {
                    if (e != null) {
                        inFlight.compareAndSet(future, null);
                        completeExceptionallyOrWithPrevious(future, e);
                    }
                    else {
                        CacheState updated = applyUpdate(cache, metadataBLOB, LocalDate.now(clock));
                        cache = updated;
                        inFlight.compareAndSet(future, null);
                        future.complete(updated.blob);
                    }
                });
                return future;
            }
        }
    }

    protected abstract @NotNull CompletionStage<MetadataBLOB> doProvide();

    static boolean needsMetadataBLOBUpdate(@Nullable CacheState cache, @NotNull Clock clock){
        if(cache == null){
            return true;
        }
        LocalDate today = LocalDate.now(clock);
        LocalDate nextUpdate = cache.blob.getPayload().getNextUpdate();
        return (nextUpdate.isBefore(today) || nextUpdate.isEqual(today)) && cache.lastUpdate.isBefore(today);
    }

    private void completeExceptionallyOrWithPrevious(@NotNull CompletableFuture<MetadataBLOB> future, @NotNull Throwable e) {
        CacheState current = cache;
        if(current != null){
            // Keep serving the last complete generation when refresh fails.
            // The next provide() call will retry the refresh.
            future.complete(current.blob);
        }
        else {
            future.completeExceptionally(e);
        }
    }

    static @NotNull CacheState applyUpdate(@Nullable CacheState current, @NotNull MetadataBLOB candidate, @NotNull LocalDate today) {
        if(current == null || isAcceptable(current.blob, candidate)){
            return new CacheState(candidate, today);
        }
        // Keep the previously published generation. Recording the attempt prevents
        // the same older BLOB from being fetched repeatedly on the same day.
        return new CacheState(current.blob, today);
    }

    private static boolean isAcceptable(@NotNull MetadataBLOB cached, @NotNull MetadataBLOB candidate) {
        Integer candidateNo = candidate.getPayload().getNo();
        Integer cachedNo = cached.getPayload().getNo();
        if(candidateNo == null || cachedNo == null){
            return Objects.equals(candidate.getPayload(), cached.getPayload());
        }
        if(candidateNo > cachedNo){
            return true;
        }
        // A re-published BLOB with the same generation is accepted only when it is
        // equivalent to the cached one. Otherwise it could replace trust material
        // without advancing the generation.
        return candidateNo.equals(cachedNo)
                && Objects.equals(candidate.getPayload(), cached.getPayload());
    }

    static class CacheState {
        final MetadataBLOB blob;
        final LocalDate lastUpdate;

        CacheState(@NotNull MetadataBLOB blob, @NotNull LocalDate lastUpdate) {
            this.blob = blob;
            this.lastUpdate = lastUpdate;
        }
    }

}
