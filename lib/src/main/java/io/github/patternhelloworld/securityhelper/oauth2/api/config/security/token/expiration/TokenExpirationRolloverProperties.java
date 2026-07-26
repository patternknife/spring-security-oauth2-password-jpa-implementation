package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.expiration;

import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.time.DateTimeException;
import java.time.ZoneId;

/**
 *  Rollover settings for a single token type (access or refresh).
 *
 *  <p>When enabled, the expiration is pushed ("rolled over") to the next occurrence of {@code hour}
 *  in the resolved time zone, on or after {@code issuedAt + TTL}. The zone is resolved as:</p>
 *  <ol>
 *      <li>the user's zone from the {@code X-Zone-Id} header, if {@code zoneHeaderEnabled} and the header is a valid ZoneId</li>
 *      <li>otherwise the fixed {@code zoneId} configured in properties</li>
 *      <li>if neither is available, no rollover is applied (pure TTL)</li>
 *  </ol>
 */
@Getter
public final class TokenExpirationRolloverProperties {

    private final boolean enabled;
    private final int hour;
    @Nullable
    private final ZoneId zoneId;
    private final boolean zoneHeaderEnabled;

    private TokenExpirationRolloverProperties(boolean enabled, int hour, @Nullable ZoneId zoneId, boolean zoneHeaderEnabled) {
        if (hour < 0 || hour > 23) {
            throw new IllegalArgumentException("Token expiration rollover hour must be between 0 and 23, but was " + hour);
        }
        this.enabled = enabled;
        this.hour = hour;
        this.zoneId = zoneId;
        this.zoneHeaderEnabled = zoneHeaderEnabled;
    }

    /**
     * @param zoneId a fixed fallback ZoneId such as "Asia/Seoul", or blank for none
     * @throws IllegalArgumentException on an invalid hour or ZoneId, to fail fast at boot
     */
    public static TokenExpirationRolloverProperties of(boolean enabled, int hour, @Nullable String zoneId, boolean zoneHeaderEnabled) {
        ZoneId parsedZoneId = null;
        if (StringUtils.hasText(zoneId)) {
            try {
                parsedZoneId = ZoneId.of(zoneId.trim());
            } catch (DateTimeException e) {
                throw new IllegalArgumentException("Invalid token expiration rollover zone-id : " + zoneId, e);
            }
        }
        return new TokenExpirationRolloverProperties(enabled, hour, parsedZoneId, zoneHeaderEnabled);
    }

    public static TokenExpirationRolloverProperties disabled() {
        return new TokenExpirationRolloverProperties(false, 0, null, false);
    }

}
