package io.github.patternhelloworld.securityhelper.oauth2.api.config.util;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.domain.traditionaloauth.bo.BasicTokenResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class EasyPlusOAuth2EndpointUtils {

    private EasyPlusOAuth2EndpointUtils() {
    }

    /*
    *   API
    *
    *   The following 8 values will be passed through the whole authorization process to be parts of "Oauth2Authorization".
    *
            "password" -> ""
            "grant_type" -> "password"
            "App-Token" -> ""
            "User-Agent" -> "PostmanRuntime/7.37.0"
            "X-Forwarded-For" -> ""
            "otp_value" -> "555555"
            "username" -> "",
            "client_id" -> ""
    *
   * */
    public static Map<String, Object> getApiParametersContainingEasyPlusHeaders(HttpServletRequest request){

        Map<String, Object> allParameters = new HashMap<>();

        MultiValueMap<String, String> parameters = "GET".equals(request.getMethod())
                ? EasyPlusOAuth2EndpointUtils.getQueryParameters(request) : EasyPlusOAuth2EndpointUtils.getFormParameters(request);


        parameters.forEach((key, value) -> {
            allParameters.put(key, value.get(0));
        });

        allParameters.put(EasyPlusHttpHeaders.APP_TOKEN, request.getHeader(EasyPlusHttpHeaders.APP_TOKEN));
        allParameters.put(EasyPlusHttpHeaders.USER_AGENT, request.getHeader(EasyPlusHttpHeaders.USER_AGENT));
        allParameters.put(EasyPlusHttpHeaders.X_Forwarded_For, request.getHeader(EasyPlusHttpHeaders.X_Forwarded_For));
        allParameters.put(EasyPlusHttpHeaders.X_ZONE_ID, request.getHeader(EasyPlusHttpHeaders.X_ZONE_ID));

        if(!allParameters.containsKey("client_id") || StringUtils.isEmpty((String)allParameters.get("client_id"))){
            BasicTokenResolver.BasicCredentials basicCredentials = BasicTokenResolver.parse(request.getHeader("Authorization")).orElseThrow(EasyPlusOauth2AuthenticationException::new);
            allParameters.put("client_id", basicCredentials.getClientId());
        }

        return allParameters;
    }


    public static MultiValueMap<String, String> getWebParametersContainingEasyPlusHeaders(HttpServletRequest request) {

        MultiValueMap<String, String> allParameters = "GET".equals(request.getMethod())
                ? EasyPlusOAuth2EndpointUtils.getQueryParameters(request)
                : EasyPlusOAuth2EndpointUtils.getFormParameters(request);

        String userAgent = request.getHeader(EasyPlusHttpHeaders.USER_AGENT);
        if (userAgent != null) {
            allParameters.add(EasyPlusHttpHeaders.USER_AGENT, userAgent);
        }

        String xForwardedFor = request.getHeader(EasyPlusHttpHeaders.X_Forwarded_For);
        if (xForwardedFor != null) {
            allParameters.add(EasyPlusHttpHeaders.X_Forwarded_For, xForwardedFor);
        }

        String xZoneId = request.getHeader(EasyPlusHttpHeaders.X_ZONE_ID);
        if (xZoneId != null) {
            allParameters.add(EasyPlusHttpHeaders.X_ZONE_ID, xZoneId);
        }

        return allParameters;
    }



    public static MultiValueMap<String, String> getFormParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameterMap.forEach((key, values) -> {
            String queryString = org.springframework.util.StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
            // If not query parameter then it's a form parameter
            if (!queryString.contains(key) && values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }

    public static MultiValueMap<String, String> getQueryParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameterMap.forEach((key, values) -> {
            String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
            if (queryString.contains(key) && values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }

    public static Map<String, Object> getParametersIfMatchesAuthorizationCodeGrantRequest(HttpServletRequest request,
                                                                                   String... exclusions) {
        if (!matchesAuthorizationCodeGrantRequest(request)) {
            return Collections.emptyMap();
        }
        MultiValueMap<String, String> multiValueParameters = "GET".equals(request.getMethod())
                ? getQueryParameters(request) : getFormParameters(request);
        for (String exclusion : exclusions) {
            multiValueParameters.remove(exclusion);
        }

        Map<String, Object> parameters = new HashMap<>();
        multiValueParameters.forEach(
                (key, value) -> parameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0])));

        return parameters;
    }

    public static boolean matchesAuthorizationCodeGrantRequest(HttpServletRequest request) {
        return AuthorizationGrantType.AUTHORIZATION_CODE.getValue()
                .equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                && request.getParameter(OAuth2ParameterNames.CODE) != null;
    }

    public static boolean matchesPkceTokenRequest(HttpServletRequest request) {
        return matchesAuthorizationCodeGrantRequest(request)
                && request.getParameter(PkceParameterNames.CODE_VERIFIER) != null;
    }

    public static Map<String, Object> convertMultiValueMapToMap(MultiValueMap<String, String> multiValueMap) {
        Map<String, Object> resultMap = new HashMap<>();

        multiValueMap.forEach((key, value) -> {
            resultMap.put(key, value.size() == 1 ? value.get(0) : String.join(",", value));
        });

        return resultMap;
    }

}
