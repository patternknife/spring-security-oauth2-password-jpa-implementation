package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.expiration;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;

/**
 *  Default {@link EasyPlusTokenExpirationPolicy}.
 *
 *  <p>Base expiration is {@code issuedAt + TTL} from the {@link RegisteredClient}'s {@code TokenSettings}
 *  (identical to the standard Spring Authorization Server behavior). When rollover is enabled for a token
 *  type, the expiration is pushed to the next occurrence of the configured hour in the resolved time zone,
 *  which keeps tokens from expiring in the middle of user flows (payments, reservations) and instead lets
 *  them expire at a low-traffic hour such as 3 AM.</p>
 *
 *  <p>Example (hour=3, zone=Asia/Seoul, access TTL=24h):</p>
 *  <ul>
 *      <li>issued 7/23 02:00 -&gt; base 7/24 02:00 -&gt; expires 7/24 03:00</li>
 *      <li>issued 7/23 03:00 -&gt; base 7/24 03:00 -&gt; expires 7/24 03:00 (already exact)</li>
 *      <li>issued 7/23 04:00 -&gt; base 7/24 04:00 -&gt; expires 7/25 03:00</li>
 *  </ul>
 *
 *  <p>Note that whichever zone a client claims via the {@code X-Zone-Id} header, the maximum extension is
 *  bounded by the rollover window (&lt; 24 hours), so the header being client-supplied gives no meaningful
 *  advantage to a malicious client.</p>
 */
public class DefaultTokenExpirationPolicy implements EasyPlusTokenExpirationPolicy {

    private final TokenExpirationRolloverProperties accessRollover;
    private final TokenExpirationRolloverProperties refreshRollover;

    public DefaultTokenExpirationPolicy(TokenExpirationRolloverProperties accessRollover,
                                        TokenExpirationRolloverProperties refreshRollover) {
        this.accessRollover = accessRollover;
        this.refreshRollover = refreshRollover;
    }

    @Override
    public Instant accessTokenExpiresAt(Instant issuedAt, RegisteredClient registeredClient, @Nullable ZoneId userZone) {
        Instant base = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());
        return applyRollover(base, accessRollover, userZone);
    }

    @Override
    public Instant refreshTokenExpiresAt(Instant issuedAt, RegisteredClient registeredClient, @Nullable ZoneId userZone) {
        Instant base = issuedAt.plus(registeredClient.getTokenSettings().getRefreshTokenTimeToLive());
        return applyRollover(base, refreshRollover, userZone);
    }

    private static Instant applyRollover(Instant base, TokenExpirationRolloverProperties rollover, @Nullable ZoneId userZone) {
        if (!rollover.isEnabled()) {
            return base;
        }
        ZoneId zone = rollover.isZoneHeaderEnabled() && userZone != null ? userZone : rollover.getZoneId();
        if (zone == null) {
            return base;
        }
        ZonedDateTime zonedBase = base.atZone(zone);
        ZonedDateTime candidate = zonedBase.toLocalDate().atTime(rollover.getHour(), 0).atZone(zone);
        if (candidate.isBefore(zonedBase)) {
            candidate = candidate.plusDays(1);
        }
        return candidate.toInstant();
    }

}
