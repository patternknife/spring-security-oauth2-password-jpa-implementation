package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.expiration;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultTokenExpirationPolicyTest {

    private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");
    private static final ZoneId NEW_YORK = ZoneId.of("America/New_York");

    private RegisteredClient registeredClient(Duration accessTtl, Duration refreshTtl) {
        return RegisteredClient.withId("client-id")
                .clientId("client_customer")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(accessTtl)
                        .refreshTokenTimeToLive(refreshTtl)
                        .build())
                .build();
    }

    private static Instant seoul(String localDateTime) {
        return ZonedDateTime.of(java.time.LocalDateTime.parse(localDateTime), SEOUL).toInstant();
    }

    @Test
    void rolloverDisabled_returnsPlainTtl() {
        DefaultTokenExpirationPolicy policy = new DefaultTokenExpirationPolicy(
                TokenExpirationRolloverProperties.disabled(), TokenExpirationRolloverProperties.disabled());
        RegisteredClient client = registeredClient(Duration.ofHours(24), Duration.ofDays(14));

        Instant issuedAt = seoul("2026-07-23T02:00:00");

        assertThat(policy.accessTokenExpiresAt(issuedAt, client, null))
                .isEqualTo(issuedAt.plus(Duration.ofHours(24)));
        assertThat(policy.refreshTokenExpiresAt(issuedAt, client, null))
                .isEqualTo(issuedAt.plus(Duration.ofDays(14)));
    }

    @Test
    void rolloverEnabledWithFixedZone_rollsUpToNextRolloverHour() {
        DefaultTokenExpirationPolicy policy = new DefaultTokenExpirationPolicy(
                TokenExpirationRolloverProperties.of(true, 3, "Asia/Seoul", false),
                TokenExpirationRolloverProperties.disabled());
        RegisteredClient client = registeredClient(Duration.ofHours(24), Duration.ofDays(14));

        // issued 7/23 02:00 -> base 7/24 02:00 -> rolled up to 7/24 03:00
        assertThat(policy.accessTokenExpiresAt(seoul("2026-07-23T02:00:00"), client, null))
                .isEqualTo(seoul("2026-07-24T03:00:00"));

        // issued 7/23 03:00 -> base 7/24 03:00 -> already exact, stays
        assertThat(policy.accessTokenExpiresAt(seoul("2026-07-23T03:00:00"), client, null))
                .isEqualTo(seoul("2026-07-24T03:00:00"));

        // issued 7/23 04:00 -> base 7/24 04:00 -> next day 03:00
        assertThat(policy.accessTokenExpiresAt(seoul("2026-07-23T04:00:00"), client, null))
                .isEqualTo(seoul("2026-07-25T03:00:00"));
    }

    @Test
    void rolloverEnabledWithoutAnyZone_fallsBackToPlainTtl() {
        DefaultTokenExpirationPolicy policy = new DefaultTokenExpirationPolicy(
                TokenExpirationRolloverProperties.of(true, 3, "", false),
                TokenExpirationRolloverProperties.disabled());
        RegisteredClient client = registeredClient(Duration.ofHours(24), Duration.ofDays(14));

        Instant issuedAt = seoul("2026-07-23T02:00:00");
        assertThat(policy.accessTokenExpiresAt(issuedAt, client, null))
                .isEqualTo(issuedAt.plus(Duration.ofHours(24)));
    }

    @Test
    void zoneHeaderEnabled_userZoneTakesPrecedenceOverFixedZone() {
        DefaultTokenExpirationPolicy policy = new DefaultTokenExpirationPolicy(
                TokenExpirationRolloverProperties.of(true, 3, "Asia/Seoul", true),
                TokenExpirationRolloverProperties.disabled());
        RegisteredClient client = registeredClient(Duration.ofHours(24), Duration.ofDays(14));

        Instant issuedAt = ZonedDateTime.of(java.time.LocalDateTime.parse("2026-07-23T02:00:00"), NEW_YORK).toInstant();

        Instant expiresAt = policy.accessTokenExpiresAt(issuedAt, client, NEW_YORK);
        assertThat(expiresAt)
                .isEqualTo(ZonedDateTime.of(java.time.LocalDateTime.parse("2026-07-24T03:00:00"), NEW_YORK).toInstant());
    }

    @Test
    void zoneHeaderDisabled_userZoneIsIgnored() {
        DefaultTokenExpirationPolicy policy = new DefaultTokenExpirationPolicy(
                TokenExpirationRolloverProperties.of(true, 3, "Asia/Seoul", false),
                TokenExpirationRolloverProperties.disabled());
        RegisteredClient client = registeredClient(Duration.ofHours(24), Duration.ofDays(14));

        assertThat(policy.accessTokenExpiresAt(seoul("2026-07-23T02:00:00"), client, NEW_YORK))
                .isEqualTo(seoul("2026-07-24T03:00:00"));
    }

    @Test
    void refreshRollover_appliesIndependentlyFromAccess() {
        DefaultTokenExpirationPolicy policy = new DefaultTokenExpirationPolicy(
                TokenExpirationRolloverProperties.disabled(),
                TokenExpirationRolloverProperties.of(true, 3, "Asia/Seoul", false));
        RegisteredClient client = registeredClient(Duration.ofHours(24), Duration.ofDays(14));

        Instant issuedAt = seoul("2026-07-23T02:00:00");

        // access stays pure TTL
        assertThat(policy.accessTokenExpiresAt(issuedAt, client, null))
                .isEqualTo(issuedAt.plus(Duration.ofHours(24)));
        // refresh base 8/6 02:00 -> rolled up to 8/6 03:00
        assertThat(policy.refreshTokenExpiresAt(issuedAt, client, null))
                .isEqualTo(seoul("2026-08-06T03:00:00"));
    }

    @Test
    void invalidConfiguration_failsFast() {
        assertThatThrownBy(() -> TokenExpirationRolloverProperties.of(true, 24, "Asia/Seoul", false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TokenExpirationRolloverProperties.of(true, 3, "Not/AZone", false))
                .isInstanceOf(IllegalArgumentException.class);
    }

}
