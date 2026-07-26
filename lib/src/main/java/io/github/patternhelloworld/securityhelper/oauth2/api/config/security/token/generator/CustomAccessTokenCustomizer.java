package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.generator;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.expiration.EasyPlusTokenExpirationPolicy;
import org.springframework.lang.Nullable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.time.Instant;
import java.time.ZoneId;

public class CustomAccessTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final String clientId;
    private final UserDetails userDetails;
    @Nullable
    private final EasyPlusTokenExpirationPolicy tokenExpirationPolicy;
    @Nullable
    private final ZoneId userZone;

    public CustomAccessTokenCustomizer(String clientId, UserDetails userDetails) {
        this(clientId, userDetails, null, null);
    }

    public CustomAccessTokenCustomizer(String clientId, UserDetails userDetails,
                                       @Nullable EasyPlusTokenExpirationPolicy tokenExpirationPolicy,
                                       @Nullable ZoneId userZone) {
        this.clientId = clientId;
        this.userDetails = userDetails;
        this.tokenExpirationPolicy = tokenExpirationPolicy;
        this.userZone = userZone;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        if (context == null) {
            throw new IllegalArgumentException("JwtEncodingContext cannot be null");
        }
        context.getClaims().claim("client_id", clientId);
        context.getClaims().claim("username", this.userDetails.getUsername());

        // Override the "exp" claim here so the JWT itself and the persisted expiration stay consistent
        // (local JWT decoding and database introspection must agree on the same expiration).
        if (tokenExpirationPolicy != null) {
            context.getClaims().claims(claims -> {
                Object iat = claims.get(JwtClaimNames.IAT);
                Instant issuedAt = iat instanceof Instant ? (Instant) iat : Instant.now();
                Instant expiresAt = tokenExpirationPolicy.accessTokenExpiresAt(issuedAt, context.getRegisteredClient(), userZone);
                if (expiresAt != null) {
                    claims.put(JwtClaimNames.EXP, expiresAt);
                }
            });
        }
    }

}
