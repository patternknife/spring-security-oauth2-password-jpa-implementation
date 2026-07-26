package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.expiration;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.time.ZoneId;

/**
 *  Strategy for calculating token expiration instants.
 *
 *  <p>The default implementation ({@link DefaultTokenExpirationPolicy}) simply applies the TTLs
 *  defined in the {@link RegisteredClient}'s {@code TokenSettings}, optionally rolling the expiration
 *  over to a configured low-traffic hour (e.g. 3 AM in the user's or a fixed time zone) to prevent
 *  users from being logged out in the middle of long flows such as payments or reservations.</p>
 *
 *  <p>Consuming applications can register their own bean of this type to fully replace
 *  the expiration policy. (The library registers the default with {@code @ConditionalOnMissingBean}.)</p>
 *
 * @see DefaultTokenExpirationPolicy
 */
public interface EasyPlusTokenExpirationPolicy {

    /**
     * @param issuedAt the instant the access token is issued at
     * @param registeredClient the client the token is issued for
     * @param userZone the user's time zone parsed from the {@code X-Zone-Id} request header, or {@code null} if absent/invalid
     * @return the expiration instant for the access token
     */
    Instant accessTokenExpiresAt(Instant issuedAt, RegisteredClient registeredClient, @Nullable ZoneId userZone);

    /**
     * @param issuedAt the instant the refresh token is issued at
     * @param registeredClient the client the token is issued for
     * @param userZone the user's time zone parsed from the {@code X-Zone-Id} request header, or {@code null} if absent/invalid
     * @return the expiration instant for the refresh token
     */
    Instant refreshTokenExpiresAt(Instant issuedAt, RegisteredClient registeredClient, @Nullable ZoneId userZone);

}
