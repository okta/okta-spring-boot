package com.okta.spring.oauth.code;

import com.okta.spring.common.OktaOAuthProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import javax.servlet.Filter;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableConfigurationProperties(OktaOAuthProperties.class)
public class OktaOAuthConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    @Autowired
    private OktaOAuthProperties oktaOAuthProperties;

    @Autowired
    private PrincipalExtractor principalExtractor;

    @Autowired
    private AuthoritiesExtractor authoritiesExtractor;

    @Autowired
    private RestTemplate restTemplate;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // add the SSO Filter
        http.addFilterBefore(ssoFilter(), UsernamePasswordAuthenticationFilter.class);

        // configure the local login page if we have one, otherwise redirect
        String loginPage = oktaOAuthProperties.getCustomLoginRoute();
        if (!StringUtils.hasText(loginPage)) {
            loginPage = oktaOAuthProperties.getRedirectUri();
        }
        http.authorizeRequests().antMatchers(loginPage).permitAll();
        http.formLogin().loginPage(oktaOAuthProperties.getRedirectUri());

        // require full auth for all other resources
        http.authorizeRequests().anyRequest().fullyAuthenticated();
    }

    private Filter ssoFilter() {

        DiscoveryMetadata discoveryMetadata = discoveryMedata();
        AuthorizationCodeResourceDetails authorizationCodeResourceDetails = authorizationCodeResourceDetails(discoveryMetadata);
        ResourceServerProperties resourceServerProperties =resourceServerProperties(discoveryMetadata);

        OAuth2ClientAuthenticationProcessingFilter oktaFilter = new OAuth2ClientAuthenticationProcessingFilter(oktaOAuthProperties.getRedirectUri());
        final OAuth2RestTemplate oktaTemplate = new OAuth2RestTemplate(authorizationCodeResourceDetails, oauth2ClientContext);
        oktaFilter.setRestTemplate(oktaTemplate);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(resourceServerProperties.getUserInfoUri(), authorizationCodeResourceDetails.getClientId()) {
            @Override
            public OAuth2Authentication loadAuthentication(String accessToken) {

                OAuth2Authentication originalOAuth = super.loadAuthentication(accessToken);
                OAuth2AccessToken existingToken = oktaTemplate.getOAuth2ClientContext()
                        .getAccessToken();

                CustomOAuth2Request customOAuth2Request = new CustomOAuth2Request(originalOAuth.getOAuth2Request());
                customOAuth2Request.setScope(existingToken.getScope());
                return new OAuth2Authentication(customOAuth2Request, originalOAuth.getUserAuthentication());
            }
        };
        tokenServices.setRestTemplate(oktaTemplate);
        tokenServices.setPrincipalExtractor(principalExtractor);
        tokenServices.setAuthoritiesExtractor(authoritiesExtractor);
        oktaFilter.setTokenServices(tokenServices);
        return oktaFilter;
    }

    private AuthorizationCodeResourceDetails authorizationCodeResourceDetails(DiscoveryMetadata discoveryMetadata) {
        AuthorizationCodeResourceDetails details = oktaOAuthProperties.getClient();

        if (!StringUtils.hasText(details.getAccessTokenUri())) {
            details.setAccessTokenUri(discoveryMetadata.getTokenEndpoint());
        }

        if (!StringUtils.hasText(details.getUserAuthorizationUri())) {
            details.setUserAuthorizationUri(discoveryMetadata.getAuthorizationEndpoint());
        }

        return details;
    }

    private ResourceServerProperties resourceServerProperties(DiscoveryMetadata discoveryMetadata) {
        ResourceServerProperties props = oktaOAuthProperties.getResource();

        if (!StringUtils.hasText(props.getUserInfoUri())) {
            props.setUserInfoUri(discoveryMetadata.getUserinfoEndpoint());
        }

        if (!StringUtils.hasText(props.getTokenInfoUri())) {
            props.setTokenInfoUri(discoveryMetadata.getIntrospectionEndpoint());
        }

        return props;
    }

    private DiscoveryMetadata discoveryMedata() {

        String discoveryUrl = oktaOAuthProperties.getDiscoveryUri();

        if (!StringUtils.hasText(discoveryUrl)) {
            discoveryUrl = oktaOAuthProperties.getIssuer() + "/.well-known/openid-configuration";
        }

        if (!StringUtils.hasText(discoveryUrl)) {
            Assert.hasText(discoveryUrl, "Unknown OIDC discovery endpoint, set property `okta.discoveryUrl` or `okta.issuer`.");
        }

        DiscoveryMetadata discoveryMetadata = restTemplate.getForObject(discoveryUrl, DiscoveryMetadata.class);

        // if we used the discovery endpoint, we need to set the issuer before we are done
        // FIXME: hackie
        if (StringUtils.hasText(discoveryUrl)) {
            oktaOAuthProperties.setIssuer(discoveryMetadata.getIssuer());
        }
        // FIXME: more hacking
        if (!StringUtils.hasText(oktaOAuthProperties.getBaseUrl())) {
            String issuer = oktaOAuthProperties.getIssuer();
            oktaOAuthProperties.setBaseUrl(issuer.substring(0, issuer.lastIndexOf("/oauth2/")));
        }


        return discoveryMetadata;
    }

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder.build();
    }

    @Bean
    PrincipalExtractor principalExtractor() {
        return map -> map.get(oktaOAuthProperties.getPrincipalClaim());
    }

    @Bean
    public AuthoritiesExtractor authoritiesExtractor() {
        return map -> {
            // extract the string groups from map
            String rolesClaimKey = oktaOAuthProperties.getRolesClaim();
            List<String> groups;
            if (map.containsKey(rolesClaimKey)) {
                groups = (List<String>) map.get(rolesClaimKey);
            } else {
                groups = Collections.emptyList();
            }

            // convert them to authorities
            return groups.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        };
    }

    public static class CustomOAuth2Request extends OAuth2Request {

        public CustomOAuth2Request(OAuth2Request other) {
            super(other);
        }

        @Override
        public void setScope(Collection<String> scope) {
            super.setScope(scope);
        }
    }
}