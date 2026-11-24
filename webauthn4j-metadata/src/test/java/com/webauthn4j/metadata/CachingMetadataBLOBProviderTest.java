package com.webauthn4j.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBPayload;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.time.LocalDate;
import java.time.Month;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@SuppressWarnings("java:S5976")
class CachingMetadataBLOBProviderTest {

    @Test
    void nextUpdate_is_past_date_test(){
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 2);
        CachingMetadataBLOBProvider target = spy(CachingMetadataBLOBProvider.class);
        when(target.doProvide()).thenReturn(createMetadataBLOB(nextUpdate));
        LocalDate firstTrialDay = LocalDate.of(2020, Month.JANUARY, 1);
        LocalDate secondTrialDay = LocalDate.of(2020, Month.JANUARY, 3);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(firstTrialDay);
            target.provide();
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(secondTrialDay);
            target.provide();
            verify(target, times(2)).doProvide();
        }
    }

    @Test
    void nextUpdate_is_today_test(){
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 2);
        CachingMetadataBLOBProvider target = spy(CachingMetadataBLOBProvider.class);
        when(target.doProvide()).thenReturn(createMetadataBLOB(nextUpdate));
        LocalDate firstTrialDay = LocalDate.of(2020, Month.JANUARY, 1);
        LocalDate secondTrialDay = LocalDate.of(2020, Month.JANUARY, 2);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(firstTrialDay);
            target.provide();
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(secondTrialDay);
            target.provide();
            verify(target, times(2)).doProvide();
        }
    }

    @Test
    void nextUpdate_is_future_date_test(){
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 3);
        CachingMetadataBLOBProvider target = spy(CachingMetadataBLOBProvider.class);
        when(target.doProvide()).thenReturn(createMetadataBLOB(nextUpdate));
        LocalDate firstTrialDay = LocalDate.of(2020, Month.JANUARY, 1);
        LocalDate secondTrialDay = LocalDate.of(2020, Month.JANUARY, 2);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(firstTrialDay);
            target.provide();
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(secondTrialDay);
            target.provide();
            verify(target, times(1)).doProvide();
        }
    }

    @Test
    void older_metadata_blob_is_rejected_test(){
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 2);
        MetadataBLOB latest = createMetadataBLOB(7, nextUpdate);
        MetadataBLOB older = createMetadataBLOB(6, nextUpdate);
        CachingMetadataBLOBProvider target = spy(CachingMetadataBLOBProvider.class);
        when(target.doProvide()).thenReturn(latest, older);

        LocalDate firstTrialDay = LocalDate.of(2020, Month.JANUARY, 1);
        LocalDate secondTrialDay = LocalDate.of(2020, Month.JANUARY, 2);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(firstTrialDay);
            assertThat(target.provide().getPayload().getNo()).isEqualTo(7);

            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(secondTrialDay);
            assertThat(target.provide().getPayload().getNo()).isEqualTo(7);
        }
        verify(target, times(2)).doProvide();
    }

    @Test
    void equivalent_metadata_blob_with_same_no_is_accepted_test(){
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 2);
        MetadataBLOB first = createMetadataBLOB(7, nextUpdate);
        MetadataBLOB republished = createMetadataBLOB(7, nextUpdate);
        CachingMetadataBLOBProvider target = spy(CachingMetadataBLOBProvider.class);
        when(target.doProvide()).thenReturn(first, republished);

        LocalDate firstTrialDay = LocalDate.of(2020, Month.JANUARY, 1);
        LocalDate secondTrialDay = LocalDate.of(2020, Month.JANUARY, 2);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(firstTrialDay);
            target.provide();

            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(secondTrialDay);
            assertThat(target.provide()).isSameAs(republished);
        }
    }

    @Test
    void non_equivalent_metadata_blob_with_same_no_is_rejected_test(){
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 2);
        MetadataBLOB first = createMetadataBLOB(7, nextUpdate);
        MetadataBLOB conflicting = createMetadataBLOB(7, LocalDate.of(2020, Month.JANUARY, 3));
        CachingMetadataBLOBProvider target = spy(CachingMetadataBLOBProvider.class);
        when(target.doProvide()).thenReturn(first, conflicting);

        LocalDate firstTrialDay = LocalDate.of(2020, Month.JANUARY, 1);
        LocalDate secondTrialDay = LocalDate.of(2020, Month.JANUARY, 2);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(firstTrialDay);
            target.provide();

            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(secondTrialDay);
            assertThat(target.provide()).isSameAs(first);
        }
    }

    @Test
    void newer_metadata_blob_is_accepted_test(){
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 2);
        MetadataBLOB older = createMetadataBLOB(7, nextUpdate);
        MetadataBLOB newer = createMetadataBLOB(8, nextUpdate);
        CachingMetadataBLOBProvider target = spy(CachingMetadataBLOBProvider.class);
        when(target.doProvide()).thenReturn(older, newer);

        LocalDate firstTrialDay = LocalDate.of(2020, Month.JANUARY, 1);
        LocalDate secondTrialDay = LocalDate.of(2020, Month.JANUARY, 2);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(firstTrialDay);
            target.provide();

            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(secondTrialDay);
            assertThat(target.provide()).isSameAs(newer);
        }
    }

    @Test
    void refresh_failure_keeps_previous_metadata_blob_test(){
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 10);
        MetadataBLOB cached = createMetadataBLOB(7, nextUpdate);
        CachingMetadataBLOBProvider target = spy(CachingMetadataBLOBProvider.class);
        when(target.doProvide()).thenReturn(cached).thenThrow(new RuntimeException("network error"));

        LocalDate trialDay = LocalDate.of(2020, Month.JANUARY, 1);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(trialDay);
            assertThat(target.provide()).isSameAs(cached);
            assertThatThrownBy(target::refresh).isInstanceOf(RuntimeException.class);
            assertThat(target.provide()).isSameAs(cached);
        }
    }

    @Test
    void refresh_failure_keeps_previous_metadata_blob_on_provide_test(){
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 2);
        MetadataBLOB cached = createMetadataBLOB(7, nextUpdate);
        CachingMetadataBLOBProvider target = spy(CachingMetadataBLOBProvider.class);
        when(target.doProvide()).thenReturn(cached).thenThrow(new RuntimeException("network error"));

        LocalDate firstTrialDay = LocalDate.of(2020, Month.JANUARY, 1);
        LocalDate secondTrialDay = LocalDate.of(2020, Month.JANUARY, 2);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(firstTrialDay);
            assertThat(target.provide()).isSameAs(cached);

            mock.when(() -> LocalDate.now(java.time.ZoneOffset.UTC)).thenReturn(secondTrialDay);
            assertThat(target.provide()).isSameAs(cached);
        }
        verify(target, times(2)).doProvide();
    }

    private MetadataBLOB createMetadataBLOB(LocalDate nextUpdate){
        return createMetadataBLOB(0, nextUpdate);
    }

    private MetadataBLOB createMetadataBLOB(int no, LocalDate nextUpdate){
        JWSFactory factory = new JWSFactory(new ObjectConverter());
        JWSHeader header = new JWSHeader(JWAIdentifier.ES256, null);
        MetadataBLOBPayload payload = new MetadataBLOBPayload("", no, nextUpdate, Collections.emptyList());
        JWS<MetadataBLOBPayload> jws = factory.create(header, payload, new byte[32]);
        return new MetadataBLOB(jws);
    }

}
