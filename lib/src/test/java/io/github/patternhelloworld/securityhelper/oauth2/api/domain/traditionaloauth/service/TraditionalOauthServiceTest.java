package io.github.patternhelloworld.securityhelper.oauth2.api.domain.traditionaloauth.service;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.CommonOAuth2AuthorizationSaverImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.DefaultOauth2AuthenticationHashCheckService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.client.CacheableRegisteredClientRepositoryImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import io.github.patternhelloworld.securityhelper.oauth2.api.domain.traditionaloauth.bo.BasicTokenResolver;
import io.github.patternhelloworld.securityhelper.oauth2.api.domain.traditionaloauth.dto.SpringSecurityTraditionalOauthDTO;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
public class TraditionalOauthServiceTest {

    @Mock
    private CacheableRegisteredClientRepositoryImpl registeredClientRepository;

    @Mock
    private OAuth2AuthorizationServiceImpl authorizationService;

    @Mock
    private ConditionalDetailsService conditionalDetailsService;

    @Mock
    private CommonOAuth2AuthorizationSaverImpl commonOAuth2AuthorizationSaver;

    @Mock
    private DefaultOauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService;

    @Mock
    private ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    @Mock
    private HttpServletRequest request;


    private TraditionalOauthService traditionalOauthService;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        traditionalOauthService = new TraditionalOauthService(registeredClientRepository, authorizationService, conditionalDetailsService, commonOAuth2AuthorizationSaver, oauth2AuthenticationHashCheckService, iSecurityUserExceptionMessageService);

    }

    @Test
    public void testCreateAccessToken_Success() throws Exception {
        // Given
        SpringSecurityTraditionalOauthDTO.TokenRequest tokenRequest = new SpringSecurityTraditionalOauthDTO.TokenRequest();
        tokenRequest.setUsername("testuser");
        tokenRequest.setPassword("testUserPassword");
        tokenRequest.setGrant_type("password");

        String testClientId = "testClientId";
        String testClientSecret = "testClientSecret";
        String credentials = testClientId + ":" + testClientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());

        String authorizationHeader = "Basic " + encodedCredentials;

        BasicTokenResolver.BasicCredentials basicCredentials = new BasicTokenResolver.BasicCredentials(testClientId, testClientSecret);

        // Mock HttpServletRequest
        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.addHeader("Authorization", authorizationHeader);

        // Mocking static methods (RequestContextHolder and BasicTokenResolver)
        try (MockedStatic<RequestContextHolder> mockedRequestContextHolder = mockStatic(RequestContextHolder.class);
             MockedStatic<BasicTokenResolver> mockedStatic = mockStatic(BasicTokenResolver.class)) {

            // Mock RequestContextHolder to return mockRequest
            ServletRequestAttributes requestAttributes = new ServletRequestAttributes(mockRequest);
            mockedRequestContextHolder.when(RequestContextHolder::currentRequestAttributes).thenReturn(requestAttributes);

            // Mock BasicTokenResolver static method to return basicCredentials
            mockedStatic.when(() -> BasicTokenResolver.parse(anyString())).thenReturn(Optional.of(basicCredentials));

            // Create a RegisteredClient instance with hashed secret
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            String hashedSecret = passwordEncoder.encode(testClientSecret); // Hash the client secret for verification

            RegisteredClient registeredClient = RegisteredClient.withId("client-id")
                    .clientId(testClientId)
                    .clientSecret(hashedSecret) // Use the hashed secret
                    .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                    .scope("read")
                    .scope("write")
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofHours(1))
                            .refreshTokenTimeToLive(Duration.ofDays(30))
                            .build())
                    .build();

            // Create a mock UserDetails instance
            UserDetails userDetails = new UserDetails() {
                @Override
                public Collection<? extends GrantedAuthority> getAuthorities() {
                    return null;
                }

                @Override
                public String getPassword() {
                    return tokenRequest.getPassword();
                }

                @Override
                public String getUsername() {
                    return tokenRequest.getUsername();
                }
            };

            // Fixed Instant values for issuedAt and expiresAt
            Instant accessTokenIssuedAt = Instant.parse("2024-09-16T12:00:00Z");
            Instant accessTokenExpiresAt = Instant.parse("2024-09-16T13:00:00Z");

            Instant refreshTokenIssuedAt = Instant.parse("2024-09-16T12:00:00Z");
            Instant refreshTokenExpiresAt = Instant.parse("2024-09-16T13:00:00Z");

            // Build OAuth2Authorization
            OAuth2Authorization oAuth2Authorization = OAuth2Authorization
                    .withRegisteredClient(registeredClient)
                    .principalName(tokenRequest.getUsername())
                    .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                    .accessToken(new OAuth2AccessToken(
                            OAuth2AccessToken.TokenType.BEARER,
                            "access-token-value",
                            accessTokenIssuedAt, // Fixed value
                            accessTokenExpiresAt, // Fixed value
                            registeredClient.getScopes()
                    ))
                    .refreshToken(new OAuth2RefreshToken(
                            "refresh-token-value",
                            refreshTokenIssuedAt, // Fixed value
                            refreshTokenExpiresAt  // Fixed value
                    ))
                    .build();

            // Mock service method responses
            when(registeredClientRepository.findByClientId(registeredClient.getClientId())).thenReturn(registeredClient);
            when(conditionalDetailsService.loadUserByUsername(tokenRequest.getUsername(), registeredClient.getClientId())).thenReturn(userDetails);

            // Create and populate a HashMap with values
            Map<String, Object> map = new HashMap<>();
            map.put("App-Token", null);
            map.put("User-Agent", null);
            map.put("X-Forwarded-For", null);
            map.put("X-Zone-Id", null);
            map.put("client_id", basicCredentials.getClientId());

            // Mock the save method of commonOAuth2AuthorizationSaver
            doReturn(oAuth2Authorization).when(commonOAuth2AuthorizationSaver).save(userDetails, new AuthorizationGrantType(tokenRequest.getGrant_type()),
                    registeredClient.getClientId(), map);

            // When calling the createAccessToken method
            SpringSecurityTraditionalOauthDTO.TokenResponse response = traditionalOauthService.createAccessToken(tokenRequest, authorizationHeader);

            // Then, verify the TokenResponse values
            assertNotNull(response);
            assertEquals(OAuth2AccessToken.TokenType.BEARER.getValue(), response.getToken_type());
            assertEquals(oAuth2Authorization.getAccessToken().getToken().getTokenValue(), response.getAccess_token());
            assertEquals(Objects.requireNonNull(oAuth2Authorization.getRefreshToken()).getToken().getTokenValue(), response.getRefresh_token());

            // Verify issuedAt and expiresAt values
            assertEquals(accessTokenIssuedAt, oAuth2Authorization.getAccessToken().getToken().getIssuedAt());
            assertEquals(accessTokenExpiresAt, oAuth2Authorization.getAccessToken().getToken().getExpiresAt());

            assertEquals(refreshTokenIssuedAt, oAuth2Authorization.getRefreshToken().getToken().getIssuedAt());
            assertEquals(refreshTokenExpiresAt, oAuth2Authorization.getRefreshToken().getToken().getExpiresAt());

            // Verify the client secret hash
            assertTrue(passwordEncoder.matches(testClientSecret, registeredClient.getClientSecret())); // Hash verification
        }
    }



}

