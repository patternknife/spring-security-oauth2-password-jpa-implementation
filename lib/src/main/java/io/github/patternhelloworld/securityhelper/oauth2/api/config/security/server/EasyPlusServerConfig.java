package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.server;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.aop.DefaultSecurityPointCut;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.aop.SecurityPointCut;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.converter.auth.endpoint.CodeAuthorizationConditionalConverter;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.converter.auth.endpoint.IntrospectionRequestConverter;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.converter.auth.endpoint.TokenRequestAfterClientBasicSecretAuthenticatedConverter;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.dao.EasyPlusAuthorizationConsentRepository;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.introspector.DefaultResourceServerTokenIntrospector;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityMessageServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.provider.auth.endpoint.authorization.CodeAuthenticationProvider;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.provider.auth.endpoint.authorization.CodeRequestAuthenticationProvider;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.provider.auth.endpoint.token.OpaqueGrantTypeAuthenticationProvider;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.provider.auth.introspectionendpoint.IntrospectOpaqueTokenAuthenticationProvider;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultApiAuthenticationFailureHandlerImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultApiAuthenticationSuccessHandlerImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultWebAuthenticationFailureHandlerImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.auth.authentication.DefaultWebAuthenticationSuccessHandlerImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.resource.authentication.DefaultAuthenticationEntryPoint;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.CommonOAuth2AuthorizationSaver;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.DefaultOauth2AuthenticationHashCheckService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationConsentServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.persistence.client.CacheableRegisteredClientRepositoryImpl;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.serivce.userdetail.ConditionalDetailsService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.expiration.DefaultTokenExpirationPolicy;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.expiration.EasyPlusTokenExpirationPolicy;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.expiration.TokenExpirationRolloverProperties;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.token.generator.CustomDelegatingOAuth2TokenGenerator;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint.authorization.CodeRequestValidator;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint.token.CodeValidationResult;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.validator.endpoint.token.TokenRequestValidator;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusOrderConstants;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.util.Map;
import java.util.function.Function;

@Order(EasyPlusOrderConstants.SECURITY_EASY_PLUS_SERVER_CONFIG_ORDER)
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class EasyPlusServerConfig {

    private static final Logger logger = LoggerFactory.getLogger(EasyPlusServerConfig.class);

    @Primary
    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder) {

        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        return new CustomDelegatingOAuth2TokenGenerator(
                jwtGenerator,
                new OAuth2RefreshTokenGenerator()
        );
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            CommonOAuth2AuthorizationSaver commonOAuth2AuthorizationSaver,
            OAuth2AuthorizationServiceImpl authorizationService,
            ConditionalDetailsService conditionalDetailsService,
            DefaultOauth2AuthenticationHashCheckService oauth2AuthenticationHashCheckService,
            OAuth2TokenGenerator<?> tokenGenerator,
            CacheableRegisteredClientRepositoryImpl cacheableRegisteredClientRepository,
            EasyPlusAuthorizationConsentRepository easyPlusAuthorizationConsentRepository,
            ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService,
            OAuth2AuthorizationConsentServiceImpl oAuth2AuthorizationConsentService,
            @Qualifier("apiAuthenticationFailureHandler") AuthenticationFailureHandler iApiAuthenticationFailureHandler,
            @Qualifier("apiAuthenticationSuccessHandler") AuthenticationSuccessHandler iApiAuthenticationSuccessHandler,
            @Qualifier("webAuthenticationFailureHandler") AuthenticationFailureHandler iWebAuthenticationFailureHandler,
            @Qualifier("webAuthenticationSuccessHandler") AuthenticationSuccessHandler iWebAuthenticationSuccessHandler,
            @Value("${patternhelloworld.securityhelper.authorization-code.consent:N}") String consentYN) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();


        http.with(authorizationServerConfigurer, Customizer.withDefaults());

        authorizationServerConfigurer
                .registeredClientRepository(cacheableRegisteredClientRepository)
                .authorizationService(authorizationService)
                .tokenGenerator(tokenGenerator)
                .oidc(Customizer.withDefaults())
                /*
                 *
                 *    Authorization Code
                 *
                 *    : /oauth2/authorize
                 *
                 *    TO DO. //  https://medium.com/@itsinil/oauth-2-1-pkce-%EB%B0%A9%EC%8B%9D-%EC%95%8C%EC%95%84%EB%B3%B4%EA%B8%B0-14500950cdbf
                 *
                 *    http://localhost:8370/oauth2/authorize?response_type=code&client_id=client_customer&state=xxx&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fcallback1
                 * */
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint
                                // Converter
                                .authorizationRequestConverter(new CodeAuthorizationConditionalConverter(easyPlusAuthorizationConsentRepository, authorizationService,  iSecurityUserExceptionMessageService, consentYN))
                                // Validation
                                .authorizationRequestConverters((authenticationConverters) ->
                                        authenticationConverters.forEach((authenticationConverter) -> {
                                            if (authenticationConverter instanceof CodeAuthorizationConditionalConverter) {
                                                CodeRequestValidator authenticationValidator =
                                                        new CodeRequestValidator(cacheableRegisteredClientRepository, iSecurityUserExceptionMessageService);

                                                ((CodeAuthorizationConditionalConverter) authenticationConverter)
                                                        .setAuthenticationValidator(authenticationValidator);
                                            }
                                        }))
                                // Provider
                                .authenticationProvider(new CodeRequestAuthenticationProvider())
                                .authenticationProvider(new CodeAuthenticationProvider())
                                // Response (Success)
                                .authorizationResponseHandler(iWebAuthenticationSuccessHandler)
                                // Response (Failure)
                                .errorResponseHandler(iWebAuthenticationFailureHandler)

                )
                /*
                 *    1) ROPC (grant_type=password, grant_type=refresh_token)
                 *    2) Authorization Code flow
                 *      - Get an "authorization_code" with "username" and "password" (grant_type=password, response_type=code)
                 *      - Login with the "code" received from Authorization Code flow instead of "username" & "password" (grant_type=authorization_code)
                 *    3) Call Order
                 *      - ClientSecretBasicAuthenticationConverter -> ClientSecretBasicAuthenticationProvider
                 *          -> OpaqueGrantTypeClientIdMandatoryAccessTokenRequestConverter
                 *              -> OpaqueGrantTypeAuthenticationProvider
                 * * */
                .clientAuthentication(clientAuthentication ->
                        clientAuthentication
                                // For Consistent Error Payloads
                                .errorResponseHandler(iApiAuthenticationFailureHandler)
                ).tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                // Converter
                                .accessTokenRequestConverter(new TokenRequestAfterClientBasicSecretAuthenticatedConverter())
                                // Validation
                                .authenticationProviders((authenticationProviders) ->
                                        authenticationProviders.forEach((authenticationProvider) -> {
                                            if (authenticationProvider instanceof OpaqueGrantTypeAuthenticationProvider) {
                                                Function<Map<String, Object>, CodeValidationResult> authenticationValidator =

                                                        new TokenRequestValidator(cacheableRegisteredClientRepository, iSecurityUserExceptionMessageService);

                                                ((OpaqueGrantTypeAuthenticationProvider) authenticationProvider)
                                                        .setAuthenticationValidator(authenticationValidator);
                                            }
                                        }))
                                // Provider
                                .authenticationProvider(new OpaqueGrantTypeAuthenticationProvider(
                                        commonOAuth2AuthorizationSaver, conditionalDetailsService, oauth2AuthenticationHashCheckService,
                                        authorizationService, iSecurityUserExceptionMessageService
                                ))

                                // Response (Success)
                                .accessTokenResponseHandler(iApiAuthenticationSuccessHandler)
                                // Response (Failure)
                                .errorResponseHandler(iApiAuthenticationFailureHandler)

                )
                /*
                *   : /oauth2/introspect
                * */
                .tokenIntrospectionEndpoint(tokenIntrospectEndpoint ->
                        tokenIntrospectEndpoint
                                // Converter
                                .introspectionRequestConverter(httpServletRequest -> new IntrospectionRequestConverter(
                                ).convert(httpServletRequest))
                                // Provider
                                .authenticationProvider(new IntrospectOpaqueTokenAuthenticationProvider(
                                      authorizationService, conditionalDetailsService
                                )));

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http.csrf(AbstractHttpConfigurer::disable)
                .securityMatcher(endpointsMatcher)
                .formLogin(formLogin -> formLogin
                        .loginPage("/login")
                        .permitAll()
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login/**", "/oauth2/**").permitAll()
                        .anyRequest().authenticated()
                ).exceptionHandling(exceptions -> exceptions.
                        authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Primary
    @Bean
    BearerTokenResolver bearerTokenResolver() {
        DefaultBearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
        bearerTokenResolver.setBearerTokenHeaderName(HttpHeaders.AUTHORIZATION);
        return bearerTokenResolver;
    }



    @Bean
    @Order(2)
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http, OAuth2AuthorizationServiceImpl authorizationService,
                                                                 ConditionalDetailsService conditionalDetailsService,
                                                                 ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService,
                                                                 AuthenticationEntryPoint iAuthenticationEntryPoint, OpaqueTokenIntrospector opaqueTokenIntrospector
    ) throws Exception {

        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        resolver.setAllowFormEncodedBodyParameter(true);

        http.csrf(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenResolver(resolver)
                        .authenticationEntryPoint(iAuthenticationEntryPoint)
                        .opaqueToken(opaqueToken -> opaqueToken.introspector(opaqueTokenIntrospector)));

        return http.build();
    }


    @Bean
    @ConditionalOnMissingBean(SecurityPointCut.class)
    public SecurityPointCut securityPointCut() {
        return new DefaultSecurityPointCut();
    }

    /*
     *   Token expiration policy
     *
     *   By default, expirations follow the TTLs in the RegisteredClient's TokenSettings (standard behavior).
     *   Enable "rollover" to push expirations to a low-traffic hour (e.g. 3 AM) so that users are not
     *   logged out in the middle of flows such as payments or reservations.
     *
     *   Zone resolution per token type: X-Zone-Id header (if zone-header-enabled) -> fixed zone-id -> pure TTL.
     *   Register your own EasyPlusTokenExpirationPolicy bean to replace this policy entirely.
     * */
    @Bean
    @ConditionalOnMissingBean(EasyPlusTokenExpirationPolicy.class)
    public EasyPlusTokenExpirationPolicy tokenExpirationPolicy(
            @Value("${patternhelloworld.securityhelper.oauth2.token.expiration.access.rollover.enabled:false}") boolean accessRolloverEnabled,
            @Value("${patternhelloworld.securityhelper.oauth2.token.expiration.access.rollover.hour:3}") int accessRolloverHour,
            @Value("${patternhelloworld.securityhelper.oauth2.token.expiration.access.rollover.zone-id:}") String accessRolloverZoneId,
            @Value("${patternhelloworld.securityhelper.oauth2.token.expiration.access.rollover.zone-header-enabled:false}") boolean accessRolloverZoneHeaderEnabled,
            @Value("${patternhelloworld.securityhelper.oauth2.token.expiration.refresh.rollover.enabled:false}") boolean refreshRolloverEnabled,
            @Value("${patternhelloworld.securityhelper.oauth2.token.expiration.refresh.rollover.hour:3}") int refreshRolloverHour,
            @Value("${patternhelloworld.securityhelper.oauth2.token.expiration.refresh.rollover.zone-id:}") String refreshRolloverZoneId,
            @Value("${patternhelloworld.securityhelper.oauth2.token.expiration.refresh.rollover.zone-header-enabled:false}") boolean refreshRolloverZoneHeaderEnabled) {
        return new DefaultTokenExpirationPolicy(
                TokenExpirationRolloverProperties.of(accessRolloverEnabled, accessRolloverHour, accessRolloverZoneId, accessRolloverZoneHeaderEnabled),
                TokenExpirationRolloverProperties.of(refreshRolloverEnabled, refreshRolloverHour, refreshRolloverZoneId, refreshRolloverZoneHeaderEnabled));
    }

    @Bean
    @ConditionalOnMissingBean(ISecurityUserExceptionMessageService.class)
    public ISecurityUserExceptionMessageService securityUserExceptionMessageService() {
        return new DefaultSecurityMessageServiceImpl();
    }


    /*
     *    Auth
     * */


    // API : Generally for ROPC

    @Bean(name = "apiAuthenticationFailureHandler")
    @ConditionalOnMissingBean(name = "apiAuthenticationFailureHandler")
    public AuthenticationFailureHandler iApiAuthenticationFailureHandler(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultApiAuthenticationFailureHandlerImpl(iSecurityUserExceptionMessageService);
    }
    @Bean(name = "apiAuthenticationSuccessHandler")
    @ConditionalOnMissingBean(name = "apiAuthenticationSuccessHandler")
    public AuthenticationSuccessHandler iApiAuthenticationSuccessHandler(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultApiAuthenticationSuccessHandlerImpl(iSecurityUserExceptionMessageService);
    }


    // WEB : Generally for Authorization Code

    @Bean(name = "webAuthenticationFailureHandler")
    @ConditionalOnMissingBean(name = "webAuthenticationFailureHandler")
    public AuthenticationFailureHandler iWebAuthenticationFailureHandler(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultWebAuthenticationFailureHandlerImpl(iSecurityUserExceptionMessageService);
    }
    @Bean(name = "webAuthenticationSuccessHandler")
    @ConditionalOnMissingBean(name = "webAuthenticationSuccessHandler")
    public AuthenticationSuccessHandler iWebAuthenticationSuccessHandler(ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        return new DefaultWebAuthenticationSuccessHandlerImpl(iSecurityUserExceptionMessageService);
    }



    /*
     *    Resource
     * */
    @Bean
    @ConditionalOnMissingBean(AuthenticationEntryPoint.class)
    public AuthenticationEntryPoint iAuthenticationEntryPoint(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        return new DefaultAuthenticationEntryPoint(resolver);
    }

    @Bean
    @ConditionalOnMissingBean(OpaqueTokenIntrospector.class)
    public OpaqueTokenIntrospector tokenIntrospector(OAuth2AuthorizationServiceImpl authorizationService,
                                                     ConditionalDetailsService conditionalDetailsService, ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService,
                                                     @Value("${patternhelloworld.securityhelper.oauth2.introspection.type:database}") String introspectionType,
                                                     @Value("${patternhelloworld.securityhelper.oauth2.introspection.uri:default-introspect-uri}") String introspectionUri,
                                                     @Value("${patternhelloworld.securityhelper.oauth2.introspection.client-id:default-client-id}") String clientId,
                                                     @Value("${patternhelloworld.securityhelper.oauth2.introspection.client-secret:default-client-secret}") String clientSecret,
                                                     JwtDecoder jwtDecoder) {
        return new DefaultResourceServerTokenIntrospector(authorizationService, conditionalDetailsService, iSecurityUserExceptionMessageService, introspectionType, introspectionUri, clientId, clientSecret, jwtDecoder);
    }
}
