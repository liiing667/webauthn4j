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

import com.webauthn4j.metadata.data.MetadataBLOB;
import org.jetbrains.annotations.NotNull;

import java.time.LocalDate;
import java.time.ZoneOffset;

public abstract class CachingMetadataBLOBProvider implements MetadataBLOBProvider {

    private MetadataBLOB cachedMetadataBLOB;
    private LocalDate cachedMetadataBLOBLastUpdate = null;
    private final Object cachedMetadataBLOBLock = new Object();

    @Override
    public @NotNull MetadataBLOB provide(){
        synchronized (cachedMetadataBLOBLock){
            LocalDate today = LocalDate.now(ZoneOffset.UTC);
            if(needsRefresh(today)){
                doRefresh(today);
            }
            return cachedMetadataBLOB;
        }
    }

    public void refresh(){
        synchronized (cachedMetadataBLOBLock){
            doRefresh(LocalDate.now(ZoneOffset.UTC));
        }
    }

    private boolean needsRefresh(@NotNull LocalDate today){
        if(cachedMetadataBLOB == null){
            return true;
        }
        LocalDate nextUpdate = cachedMetadataBLOB.getPayload().getNextUpdate();
        return (nextUpdate.isBefore(today) || nextUpdate.isEqual(today)) && cachedMetadataBLOBLastUpdate.isBefore(today);
    }

    private void doRefresh(@NotNull LocalDate today){
        // Publish the blob and its timestamp together only after doProvide has completely validated the candidate.
        MetadataBLOB candidate = doProvide();
        cachedMetadataBLOB = candidate;
        cachedMetadataBLOBLastUpdate = today;
    }

    protected abstract @NotNull MetadataBLOB doProvide();


}
