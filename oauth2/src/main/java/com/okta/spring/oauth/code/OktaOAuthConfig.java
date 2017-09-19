package com.okta.spring.oauth.code;

import com.okta.spring.oauth.OktaOAuthProperties;
import com.okta.spring.oauth.discovery.DiscoveryMetadata;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.OAuth2ClientConfiguration;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import javax.servlet.Filter;
import java.util.function.Consumer;

@Configuration
@ConditionalOnClass({OAuth2ClientConfiguration.class})
@ConditionalOnBean(OAuth2ClientConfiguration.class)
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


    @PostConstruct
    protected void init() {
        // query the discovery endpoint and then update the OAuth properties
        DiscoveryMetadata discoveryMetadata = discoveryMetadata();

        updateIfNotSet(oktaOAuthProperties.getOauth2()::setIssuer,
                       oktaOAuthProperties.getOauth2().getIssuer(),
                       discoveryMetadata.getIssuer());

        String issuer = oktaOAuthProperties.getOauth2().getIssuer();
        String baseUrl = issuer.substring(0, issuer.lastIndexOf("/oauth2/"));

        updateIfNotSet(oktaOAuthProperties.getClient()::setOrgUrl,
                       oktaOAuthProperties.getClient().getOrgUrl(),
                       baseUrl);

        updateAuthorizationCodeResourceDetails(discoveryMetadata);
        updateResourceServerProperties(discoveryMetadata);
    }

    // TODO: there must be some nice Spring way to merge multiple ConfigurationProperties
    private AuthorizationCodeResourceDetails updateAuthorizationCodeResourceDetails(DiscoveryMetadata discoveryMetadata) {
        AuthorizationCodeResourceDetails details = authorizationCodeResourceDetails();

        updateIfNotSet(details::setClientId,
                       details.getClientId(),
                       oktaOAuthProperties.getOauth2().getClientId());

        updateIfNotSet(details::setClientSecret,
                       details.getClientSecret(),
                       oktaOAuthProperties.getOauth2().getClientSecret());

        updateIfNotSet(details::setAccessTokenUri,
                       details.getAccessTokenUri(),
                       discoveryMetadata.getTokenEndpoint());

        updateIfNotSet(details::setUserAuthorizationUri,
                       details.getUserAuthorizationUri(),
                       discoveryMetadata.getAuthorizationEndpoint());

        return details;
    }

    /**
     * If {code}currentValue{code} is empty, then {code}newValue{code} is applied to {code}setter{code}.
     * @param setter method to call to update value if needed
     * @param currentValue the current value to be checked if not empty
     * @param newValue new value to use if the consumer needs to be called
     */
    private void updateIfNotSet(Consumer<String> setter, String currentValue, String newValue) {
        if (!StringUtils.hasText(currentValue)) {
            setter.accept(newValue);
        }
    }

    private ResourceServerProperties updateResourceServerProperties(DiscoveryMetadata discoveryMetadata) {
        ResourceServerProperties props = resourceServerProperties();

        updateIfNotSet(props::setUserInfoUri,
                       props.getUserInfoUri(),
                       discoveryMetadata.getUserinfoEndpoint());

        updateIfNotSet(props::setTokenInfoUri,
                       props.getTokenInfoUri(),
                       discoveryMetadata.getIntrospectionEndpoint());
        return props;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // FIXME: MVC bleed
        http.authorizeRequests().antMatchers("/okta/*.css").permitAll();

        // add the SSO Filter
        http.addFilterBefore(ssoFilter(), UsernamePasswordAuthenticationFilter.class);

        // configure the local login page if we have one, otherwise redirect
        String loginPage = oktaOAuthProperties.getOauth2().getCustomLoginRoute();
        if (!StringUtils.hasText(loginPage)) {
            loginPage = oktaOAuthProperties.getOauth2().getRedirectUri();
        }
        http.authorizeRequests().antMatchers(loginPage).permitAll();
        http.formLogin().loginPage(oktaOAuthProperties.getOauth2().getRedirectUri());

        // require full auth for all other resources
        http.authorizeRequests().anyRequest().fullyAuthenticated();
    }

    private Filter ssoFilter() {

        OAuth2ClientAuthenticationProcessingFilter oktaFilter = new OAuth2ClientAuthenticationProcessingFilter(oktaOAuthProperties.getOauth2().getRedirectUri());
        OAuth2RestTemplate oktaTemplate = new OAuth2RestTemplate(authorizationCodeResourceDetails(), oauth2ClientContext);
        oktaFilter.setRestTemplate(oktaTemplate);
        UserInfoTokenServices tokenServices = new OktaUserInfoTokenServices(resourceServerProperties().getUserInfoUri(), authorizationCodeResourceDetails().getClientId(), oauth2ClientContext);
        tokenServices.setRestTemplate(oktaTemplate);
        tokenServices.setPrincipalExtractor(principalExtractor);
        tokenServices.setAuthoritiesExtractor(authoritiesExtractor);
        oktaFilter.setTokenServices(tokenServices);
        return oktaFilter;
    }

    @Bean
    @ConfigurationProperties("security.oauth2.client")
    protected AuthorizationCodeResourceDetails authorizationCodeResourceDetails() {
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setClientAuthenticationScheme(AuthenticationScheme.form);
        details.setScope(oktaOAuthProperties.getOauth2().getScopes());
        return details;
    }

    @Bean
    @ConfigurationProperties("security.oauth2.resource")
    protected ResourceServerProperties resourceServerProperties() {
        ResourceServerProperties props = new ResourceServerProperties();
        props.setPreferTokenInfo(false);
        return props;
    }


    @Bean
    protected DiscoveryMetadata discoveryMetadata() {

        String discoveryUrl = oktaOAuthProperties.getOauth2().getDiscoveryUri();

        if (!StringUtils.hasText(discoveryUrl)) {
            discoveryUrl = oktaOAuthProperties.getOauth2().getIssuer() + "/.well-known/openid-configuration";
        }

        if (!StringUtils.hasText(discoveryUrl)) {
            Assert.hasText(discoveryUrl, "Unknown OIDC discovery endpoint, set property `okta.discoveryUrl` or `okta.issuer`.");
        }

        return restTemplate.getForObject(discoveryUrl, DiscoveryMetadata.class);
    }

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder.build();
    }

    @Bean
    PrincipalExtractor principalExtractor() {
        return new ClaimsPrincipalExtractor(oktaOAuthProperties.getOauth2().getPrincipalClaim());
    }

    @Bean
    public AuthoritiesExtractor authoritiesExtractor() {
        return new ClaimsAuthoritiesExtractor(oktaOAuthProperties.getOauth2().getRolesClaim());
    }
}