/*
 * Copyright 2018-Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.spring.boot.oauth

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.LoggerContext
import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.okta.spring.boot.oauth.config.OktaOAuth2Properties
import com.okta.spring.boot.oauth.env.OktaOAuth2PropertiesMappingEnvironmentPostProcessor
import org.slf4j.impl.StaticLoggerBinder
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.autoconfigure.logging.ConditionEvaluationReportLoggingListener
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.boot.autoconfigure.security.oauth2.client.reactive.ReactiveOAuth2ClientAutoConfiguration
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration
import org.springframework.boot.autoconfigure.security.oauth2.resource.reactive.ReactiveOAuth2ResourceServerAutoConfiguration
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration
import org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration
import org.springframework.boot.autoconfigure.security.reactive.ReactiveUserDetailsServiceAutoConfiguration
import org.springframework.boot.test.context.runner.AbstractApplicationContextRunner
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner
import org.springframework.boot.test.context.runner.WebApplicationContextRunner
import org.springframework.boot.web.reactive.context.AnnotationConfigReactiveWebApplicationContext
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.ConfigurableEnvironment
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.config.BeanIds
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler
import org.springframework.security.oauth2.client.userinfo.*
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter
import org.springframework.security.oauth2.client.web.server.authentication.OAuth2LoginAuthenticationWebFilter
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.server.MatcherSecurityWebFilterChain
import org.springframework.security.web.server.WebFilterChainProxy
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.test.util.ReflectionTestUtils
import org.springframework.web.server.WebFilter
import org.testng.TestException
import org.testng.annotations.AfterClass
import org.testng.annotations.BeforeClass
import org.testng.annotations.Test

import javax.servlet.Filter
import java.util.function.Supplier
import java.util.stream.Collectors
import java.util.stream.Stream

import static org.assertj.core.api.Assertions.assertThat

class AutoConfigConditionalTest implements HttpMock {

    private Level originalLevel = Level.INFO
    private Logger conditionLogger =  ((LoggerContext) StaticLoggerBinder.getSingleton().getLoggerFactory()).getLogger(ConditionEvaluationReportLoggingListener)

    private List<Class<?>> oktaAutoConfigs = [
        OktaOAuth2AutoConfig,
        OktaOAuth2ResourceServerAutoConfig,
        ReactiveOktaOAuth2AutoConfig,
        ReactiveOktaOAuth2ResourceServerAutoConfig,
        ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig,
        ReactiveOktaOAuth2ServerHttpServerAutoConfig,
        OAuth2ResourceServerAutoConfiguration,
        OAuth2ClientAutoConfiguration,
        ReactiveOAuth2ClientAutoConfiguration,
        ReactiveSecurityAutoConfiguration,
        ReactiveUserDetailsServiceAutoConfiguration,
        ReactiveOAuth2ResourceServerAutoConfiguration]

    @Override
    void configureHttpMock(WireMockServer wireMockServer) {
        String orgIssuer = mockBaseUrl()
        String customAsIssuer = "${mockBaseUrl()}oauth2/custom-as"
        wireMockServer.stubFor(
            WireMock.get("/oauth2/custom-as/.well-known/openid-configuration")
                .willReturn(WireMock.aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(""" {
                        "issuer": "${customAsIssuer}",
                        "subject_types_supported": ["public"],
                        "end_session_endpoint":"${customAsIssuer}v1/logout",
                        "authorization_endpoint":"${customAsIssuer}v1/authorize",
                        "token_endpoint":"${customAsIssuer}v1/token",
                        "userinfo_endpoint":"${customAsIssuer}v1/userinfo",
                        "registration_endpoint":"${customAsIssuer}v1/clients",
                        "jwks_uri":"${customAsIssuer}v1/keys",
                        "introspection_endpoint":"${customAsIssuer}v1/introspect"
                    }
                    """)))
        wireMockServer.stubFor(
            WireMock.get("/.well-known/openid-configuration")
                .willReturn(WireMock.aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(""" {
                        "issuer": "${orgIssuer}",
                        "subject_types_supported": ["public"],
                        "end_session_endpoint":"${orgIssuer}oauth2/v1/logout",
                        "authorization_endpoint":"${orgIssuer}oauth2/v1/authorize",
                        "token_endpoint":"${orgIssuer}oauth2/v1/token",
                        "userinfo_endpoint":"${orgIssuer}oauth2/v1/userinfo",
                        "registration_endpoint":"${orgIssuer}oauth2/v1/clients",
                        "jwks_uri":"${orgIssuer}oauth2/v1/keys",
                        "introspection_endpoint":"${orgIssuer}oauth2/v1/introspect"
                    }
                    """)))
    }


    @BeforeClass
    void enableVerboseConditionEvaluationLogging() {
        originalLevel = conditionLogger.getLevel()
    }

    @AfterClass
    void disableVerboseConditionEvaluationLogging() {
        conditionLogger.setLevel(originalLevel)
    }

    @Test
    void webResourceServerConfig_emptyProperties() {

        // missing properties, component does not load
        webContextRunner()
            .run { context ->
                assertThat(context).doesNotHaveBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(JwtDecoder)
                assertThat(context).doesNotHaveBean(OktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(OAuth2AuthorizedClientService)
                assertThat(context).doesNotHaveBean(AuthoritiesProvider)

                assertFiltersDisabled(context, OAuth2LoginAuthenticationFilter, BearerTokenAuthenticationFilter)
        }
    }

    @Test
    void webResourceServerConfig_withIssuer() {

        // with properties it loads correctly
        webContextRunner().withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as")
            .run { context ->
                assertThat(context).hasSingleBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(JwtDecoder)
                assertThat(context).hasSingleBean(OktaJwtAuthenticationConverter)
                assertThat(context).doesNotHaveBean(OktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(OAuth2AuthorizedClientService)
                assertThat(context).doesNotHaveBean(AuthoritiesProvider)

                assertFiltersEnabled(context, BearerTokenAuthenticationFilter)
                assertFiltersDisabled(context, OAuth2LoginAuthenticationFilter)
            }
    }

    @Test
    void webLoginConfig_withIssuer() {

        webContextRunner().withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as")
            .run { context ->

                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(OAuth2ClientProperties)
                assertThat(context).doesNotHaveBean(OktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(AuthoritiesProvider)

                assertThat(context).hasSingleBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(JwtDecoder)
                assertThat(context).hasSingleBean(OktaOAuth2Properties)

                assertFiltersEnabled(context, BearerTokenAuthenticationFilter)
                assertFiltersDisabled(context, OAuth2LoginAuthenticationFilter)
            }
    }

    @Test
    void webLoginConfig_withIssuer_OpaqueTokenResourceServerConfig() {

        // server should NOT start due to missing client-id and client-secret which
        // are required for creation of OpaqueTokenIntrospector bean.
        webContextRunner(OpaqueTokenResourceServerConfiguredApp).withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as")
            .run { context ->
                assertThat(context).hasFailed()
            }
    }

    @Test
    void webLoginConfig_withIssuerClientIdSecret_JwtResourceServerConfig() {

        // start context for App configured to use JWT  validation for resource server
        webContextRunner(JwtResourceServerConfiguredApp).withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
            "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
            "okta.oauth2.client-id=test-client-id",
            "okta.oauth2.client-secret=test-client-secret")
            .run { context ->

                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)

                assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")
                assertThat(context).hasSingleBean(OktaOAuth2AutoConfig)
                assertThat(context).hasSingleBean(OAuth2ClientProperties)
                assertThat(context).hasSingleBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(JwtDecoder)
                assertThat(context).hasSingleBean(OktaOAuth2Properties)

                assertFiltersEnabled(context, OAuth2LoginAuthenticationFilter, BearerTokenAuthenticationFilter)
            }
    }

    @Test
    void webLoginConfig_withRootIssuerClientIdSecret() {

        // start context for the App with NO resource server configuration and root issuer
        // root issuer would force Opaque Token configuration of resource server.
        webContextRunner().withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com",
            "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}", // work around to not validate the https url
            "okta.oauth2.client-id=test-client-id",
            "okta.oauth2.client-secret=test-client-secret")
            .run { context ->

                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)

                assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")
                assertThat(context).hasSingleBean(OktaOAuth2AutoConfig)
                assertThat(context).hasSingleBean(OAuth2ClientProperties)
                assertThat(context).hasSingleBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(OpaqueTokenIntrospector)
                assertThat(context).hasSingleBean(OktaOAuth2Properties)

                assertFiltersEnabled(context, OAuth2LoginAuthenticationFilter, BearerTokenAuthenticationFilter)
            }
    }

    @Test
    void webLoginConfig_withIssuerAndClientIdSecret() {

        webContextRunner().withPropertyValues(
                "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
                "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
                "okta.oauth2.client-id=test-client-id",
                "okta.oauth2.client-secret=test-client-secret")
            .run { context ->
            assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
            assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
            assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
            assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
            assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2UserService)
            assertThat(context).doesNotHaveBean(ReactiveOktaOidcUserService)
            assertThat(context).doesNotHaveBean(OidcClientInitiatedServerLogoutSuccessHandler)

            assertThat(context).hasSingleBean(OktaOAuth2ResourceServerAutoConfig)
            assertThat(context).hasSingleBean(JwtDecoder)
            assertThat(context).hasSingleBean(OktaJwtAuthenticationConverter)
            assertThat(context).hasSingleBean(OAuth2ClientProperties)
            assertThat(context).hasSingleBean(OktaOAuth2Properties)
            assertThat(context).hasSingleBean(OktaOAuth2AutoConfig)
            assertThat(context).hasSingleBean(OktaOAuth2UserService)
            assertThat(context).hasSingleBean(OktaOidcUserService)
            assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")
            assertThat(context).doesNotHaveBean(OidcClientInitiatedLogoutSuccessHandler)

            assertThat(context.getEnvironment().getProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri")).isEqualTo("https://test.example.com/oauth2/custom-as")

            assertFiltersEnabled(context, OAuth2LoginAuthenticationFilter, BearerTokenAuthenticationFilter)
        }
    }

    @Test
    void webLoginConfig_withIssuerAndClientIdSecret_OpaqueTokenResourceServerConfig() {

        // start context for App configured to use Opaque Token validation for resource server
        webContextRunner(OpaqueTokenResourceServerConfiguredApp).withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
            "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
            "okta.oauth2.client-id=test-client-id",
            "okta.oauth2.client-secret=test-client-secret")
            .run { context ->

                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)

                assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")
                assertThat(context).hasSingleBean(OktaOAuth2AutoConfig)
                assertThat(context).hasSingleBean(OAuth2ClientProperties)
                assertThat(context).hasSingleBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(OpaqueTokenIntrospector)
                assertThat(context).hasSingleBean(OktaOAuth2Properties)

                assertFiltersEnabled(context, OAuth2LoginAuthenticationFilter, BearerTokenAuthenticationFilter)
            }
    }

    @Test
    void webLoginConfig_withLogoutUri() {

        webContextRunner().withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
            "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
            "okta.oauth2.client-id=test-client-id",
            "okta.oauth2.client-secret=test-client-secret",
            "okta.oauth2.postLogoutRedirectUri=http://logout.example.com")
            .run { context ->
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2UserService)
                assertThat(context).doesNotHaveBean(ReactiveOktaOidcUserService)
                assertThat(context).doesNotHaveBean(OidcClientInitiatedServerLogoutSuccessHandler)

                assertThat(context).hasSingleBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(JwtDecoder)
                assertThat(context).hasSingleBean(OAuth2ClientProperties)
                assertThat(context).hasSingleBean(OktaOAuth2Properties)
                assertThat(context).hasSingleBean(OktaOAuth2AutoConfig)
                assertThat(context).hasSingleBean(OktaOAuth2UserService)
                assertThat(context).hasSingleBean(OktaOidcUserService)
                assertThat(context).hasSingleBean(OidcClientInitiatedLogoutSuccessHandler)
                assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")
                assertThat(context.getBean(OidcClientInitiatedLogoutSuccessHandler).postLogoutRedirectUri).isEqualTo("http://logout.example.com")

                assertFiltersEnabled(context, OAuth2LoginAuthenticationFilter, BearerTokenAuthenticationFilter)
            }
    }

    @Test
    void webLoginConfig_withLogoutUriRelative() {

        webContextRunner().withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
            "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
            "okta.oauth2.client-id=test-client-id",
            "okta.oauth2.client-secret=test-client-secret",
            "okta.oauth2.postLogoutRedirectUri=/logout/callback")
            .run { context ->
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2UserService)
                assertThat(context).doesNotHaveBean(ReactiveOktaOidcUserService)
                assertThat(context).doesNotHaveBean(OidcClientInitiatedServerLogoutSuccessHandler)

                assertThat(context).hasSingleBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(JwtDecoder)
                assertThat(context).hasSingleBean(OAuth2ClientProperties)
                assertThat(context).hasSingleBean(OktaOAuth2Properties)
                assertThat(context).hasSingleBean(OktaOAuth2AutoConfig)
                assertThat(context).hasSingleBean(OktaOAuth2UserService)
                assertThat(context).hasSingleBean(OktaOidcUserService)
                assertThat(context).hasSingleBean(OidcClientInitiatedLogoutSuccessHandler)
                assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")

                assertFiltersEnabled(context, OAuth2LoginAuthenticationFilter, BearerTokenAuthenticationFilter)
                def logoutHandler = context.getBean(OidcClientInitiatedLogoutSuccessHandler)
                assertThat(logoutHandler.postLogoutRedirectUri).isEqualTo("{baseUrl}/logout/callback")
            }
    }
    @Test
    void webLoginConfig_withIssuerAndClientId_pkce() {

        webContextRunner().withPropertyValues(
                "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
                "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
                "okta.oauth2.client-id=test-client-id")
            .run { context ->
            assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
            assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
            assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
            assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)

            assertThat(context).hasSingleBean(OktaOAuth2ResourceServerAutoConfig)
            assertThat(context).hasSingleBean(JwtDecoder)
            assertThat(context).hasSingleBean(OktaJwtAuthenticationConverter)
            assertThat(context).hasSingleBean(OAuth2ClientProperties)
            assertThat(context).hasSingleBean(OktaOAuth2Properties)
            assertThat(context).hasSingleBean(OktaOAuth2AutoConfig)
            assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")

            assertFiltersEnabled(context, OAuth2LoginAuthenticationFilter, BearerTokenAuthenticationFilter)
        }
    }

    @Test
    void webLoginConfig_withRootIssuerClientIdSecret_JwtResourceServerConfig() {

        // server would start with Opaque Token validation mode since the issuer is ROOT.
        webContextRunner(JwtResourceServerConfiguredApp).withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com",
            "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}", // work around to not validate the https url
            "okta.oauth2.client-id=test-client-id",
            "okta.oauth2.client-secret=test-client-secret")
            .run { context ->
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)

                assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")
                assertThat(context).hasSingleBean(OktaOAuth2AutoConfig)
                assertThat(context).hasSingleBean(OAuth2ClientProperties)
                assertThat(context).hasSingleBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(OpaqueTokenIntrospector)
                assertThat(context).hasSingleBean(OktaOAuth2Properties)

                assertFiltersEnabled(context, OAuth2LoginAuthenticationFilter, BearerTokenAuthenticationFilter)
            }
    }

    @Test
    void webLoginConfig_withIssuerClientIdSecret_JwtAndOpaqueTokenResourceServerConfig() {

        // server should NOT start as Spring does NOT allow both JWT and Opaque Token
        // configurations at the same time.
        webContextRunner(JwtAndOpaqueTokenResourceServerConfiguredApp).withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
            "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
            "okta.oauth2.client-id=test-client-id",
            "okta.oauth2.client-secret=test-client-secret")
            .run { context ->
                assertThat(context).hasFailed()
            }
    }

    @Test
    void reactiveResourceServerTest_emptyProperties() {

        // missing properties, component does not load
        reactiveContextRunner()
            .run { context ->
                assertThat(context).doesNotHaveBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(JwtDecoder)
                assertThat(context).doesNotHaveBean(OktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(OAuth2AuthorizedClientService)
                assertThat(context).doesNotHaveBean(AuthoritiesProvider)

                assertWebFiltersDisabled(context, OAuth2LoginAuthenticationWebFilter)
            }
    }

    @Test
    void reactiveResourceServerTest_withIssuer() {

        // with properties it loads correctly
        reactiveContextRunner().withPropertyValues(
                    "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as")
            .run {context ->
                assertThat(context).doesNotHaveBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(JwtDecoder)
                assertThat(context).doesNotHaveBean(OktaOAuth2AutoConfig)

                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(OAuth2AuthorizedClientService)
                assertThat(context).doesNotHaveBean(AuthoritiesProvider)

                assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)

                assertWebFiltersDisabled(context, OAuth2LoginAuthenticationWebFilter)
                assertWebFiltersEnabled(context, AuthenticationWebFilter)
                assertJwtBearerWebFilterEnabled(context)
            }
    }

    @Test
    void reactiveLoginConfig_withIssuer() {

        reactiveContextRunner()
                .withPropertyValues(
                    "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as")
                .run { context ->
            assertThat(context).doesNotHaveBean(OktaOAuth2ResourceServerAutoConfig)
            assertThat(context).doesNotHaveBean(JwtDecoder)
            assertThat(context).doesNotHaveBean(OktaOAuth2AutoConfig)
            assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
            assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)

            assertThat(context).doesNotHaveBean(AuthoritiesProvider)
            assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
            assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)

            assertThat(context).hasSingleBean(OAuth2ClientProperties)
            assertThat(context).hasSingleBean(OktaOAuth2Properties)

            assertWebFiltersEnabled(context, AuthenticationWebFilter)
            assertJwtBearerWebFilterEnabled(context)
        }
    }

    @Test
    void reactiveLoginConfig_withIssuerAndClientIdSecret() {

        reactiveContextRunner().withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
            "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
            "okta.oauth2.client-id=test-client-id",
            "okta.oauth2.client-secret=test-client-secret")
            .run { context ->

                assertThat(context).doesNotHaveBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(JwtDecoder)
                assertThat(context).doesNotHaveBean(OktaOAuth2AutoConfig)

                assertThat(context).hasSingleBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).hasSingleBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)

                assertThat(context).hasSingleBean(OAuth2ClientProperties)
                assertThat(context).hasSingleBean(OktaOAuth2Properties)
                assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")

                assertWebFiltersEnabled(context, AuthenticationWebFilter)
                assertJwtBearerWebFilterEnabled(context)
            }
    }

    @Test
    void reactiveLoginConfig_withLogoutUri() {

        reactiveContextRunner().withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
            "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
            "okta.oauth2.client-id=test-client-id",
            "okta.oauth2.client-secret=test-client-secret",
            "okta.oauth2.postLogoutRedirectUri=http://logout.example.com")
            .run { context ->

                assertThat(context).doesNotHaveBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(JwtDecoder)
                assertThat(context).doesNotHaveBean(OktaOAuth2AutoConfig)

                assertThat(context).hasSingleBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).hasSingleBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
                assertThat(context).hasSingleBean(OidcClientInitiatedServerLogoutSuccessHandler)

                assertThat(context).hasSingleBean(OAuth2ClientProperties)
                assertThat(context).hasSingleBean(OktaOAuth2Properties)
                assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")

                assertWebFiltersEnabled(context, OAuth2LoginAuthenticationWebFilter, AuthenticationWebFilter)
                assertJwtBearerWebFilterEnabled(context)
                assertThat(context.getBean(OidcClientInitiatedServerLogoutSuccessHandler).postLogoutRedirectUri).isEqualTo("http://logout.example.com")
        }
    }

    @Test
    void reactiveLoginConfig_withIssuerAndClientIdSecret_pkce() {

        reactiveContextRunner().withPropertyValues(
                "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
                "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
                "okta.oauth2.client-id=test-client-id")
            .run { context ->

            assertThat(context).doesNotHaveBean(OktaOAuth2ResourceServerAutoConfig)
            assertThat(context).doesNotHaveBean(JwtDecoder)
            assertThat(context).doesNotHaveBean(OktaOAuth2AutoConfig)

            assertThat(context).hasSingleBean(ReactiveOktaOAuth2AutoConfig)
            assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
            assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
            assertThat(context).hasSingleBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
            assertThat(context).hasSingleBean(ReactiveOktaOAuth2UserService)
            assertThat(context).hasSingleBean(ReactiveOktaOidcUserService)

            assertThat(context).hasSingleBean(OAuth2ClientProperties)
            assertThat(context).hasSingleBean(OktaOAuth2Properties)
            assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")

            assertWebFiltersEnabled(context, OAuth2LoginAuthenticationWebFilter, AuthenticationWebFilter)
            assertJwtBearerWebFilterEnabled(context)
        }
    }

    @Test
    void webOverrideOidcUserService() {
        webContextRunner(OverrideWebOidcComponents).withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
            "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
            "okta.oauth2.client-id=test-client-id",
            "okta.oauth2.client-secret=test-client-secret")
            .run { context ->
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2UserService)
                assertThat(context).doesNotHaveBean(ReactiveOktaOidcUserService)

                assertThat(context).hasSingleBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(JwtDecoder)
                assertThat(context).hasSingleBean(OAuth2ClientProperties)
                assertThat(context).hasSingleBean(OktaOAuth2Properties)
                assertThat(context).hasSingleBean(OktaOAuth2AutoConfig)

                assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")
                assertThat(context).hasSingleBean(DefaultOAuth2UserService)
                assertThat(context).hasSingleBean(OidcUserService)
                assertThat(context).doesNotHaveBean(OktaOAuth2UserService)
                assertThat(context).doesNotHaveBean(OktaOidcUserService)

                assertFiltersEnabled(context, OAuth2LoginAuthenticationFilter, BearerTokenAuthenticationFilter)
            }
    }

    @Test
    void reactiveOverrideOidcUserService() {
        reactiveContextRunner(OverrideReactiveOidcComponents).withPropertyValues(
            "okta.oauth2.issuer=https://test.example.com/oauth2/custom-as",
            "spring.security.oauth2.client.provider.okta.issuerUri=${mockBaseUrl()}oauth2/custom-as", // work around to not validate the https url
            "okta.oauth2.client-id=test-client-id")
            .run { context ->

                assertThat(context).doesNotHaveBean(OktaOAuth2ResourceServerAutoConfig)
                assertThat(context).doesNotHaveBean(JwtDecoder)
                assertThat(context).doesNotHaveBean(OktaOAuth2AutoConfig)

                assertThat(context).hasSingleBean(ReactiveOktaOAuth2AutoConfig)
                assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerAutoConfig)
                assertThat(context).hasSingleBean(ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig)
                assertThat(context).hasSingleBean(ReactiveOktaOAuth2ServerHttpServerAutoConfig)
                assertThat(context).hasSingleBean(OAuth2ClientProperties)
                assertThat(context).hasSingleBean(OktaOAuth2Properties)

                assertThat(context).getBeans(AuthoritiesProvider).containsOnlyKeys("tokenScopesAuthoritiesProvider", "groupClaimsAuthoritiesProvider")
                assertThat(context).hasSingleBean(DefaultReactiveOAuth2UserService)
                assertThat(context).hasSingleBean(OidcReactiveOAuth2UserService)
                assertThat(context).doesNotHaveBean(ReactiveOktaOAuth2UserService)
                assertThat(context).doesNotHaveBean(ReactiveOktaOidcUserService)

                assertWebFiltersEnabled(context, OAuth2LoginAuthenticationWebFilter, AuthenticationWebFilter)
                assertJwtBearerWebFilterEnabled(context)
            }
    }

    private static void assertFiltersEnabled(ApplicationContext context, Class<Filter>... filters) {
        assertThat(activeFilters(context)).contains(filters)
    }

    private static void assertFiltersDisabled(ApplicationContext context, Class<Filter>... filters) {
        assertThat(activeFilters(context)).doesNotContain(filters)
    }

    private static void assertWebFiltersEnabled(ApplicationContext context, Class<WebFilter>... filters) {
        assertThat(activeWebFiltersClasses(context)).contains(filters)
    }

    private static void assertWebFiltersDisabled(ApplicationContext context, Class<WebFilter>... filters) {
        assertThat(activeWebFiltersClasses(context)).doesNotContain(filters)
    }

    private static void assertJwtBearerWebFilterEnabled(ApplicationContext context) {
        assertFilterConfiguredWithJwtAuthenticationManager(context)
    }

    private static Stream<WebFilter> activeJwtAuthenticationWebFilters(ApplicationContext context) {
        return activeWebFilters(context).stream()
                        .filter { it.getClass() == AuthenticationWebFilter }
                        .map {(AuthenticationWebFilter) it}
                        .filter {
                            // here be dragons
                            // TODO: there must be a better way to validate we have a JWT reactive auth manager
                            def field = it.class.superclass.getDeclaredField("authenticationManagerResolver")
                            field.setAccessible(true)
                            field.get(it).arg$1.getClass() == JwtReactiveAuthenticationManager
                        }
    }

    // see: https://github.com/spring-projects/spring-boot/blob/v2.3.6.RELEASE/spring-boot-project/spring-boot-autoconfigure/src/test/java/org/springframework/boot/autoconfigure/security/oauth2/resource/reactive/ReactiveOAuth2ResourceServerAutoConfigurationTests.java#L361
    static void assertFilterConfiguredWithJwtAuthenticationManager(ApplicationContext context) {
        MatcherSecurityWebFilterChain filterChain = (MatcherSecurityWebFilterChain) context.getBean(BeanIds.SPRING_SECURITY_FILTER_CHAIN)
        Stream<WebFilter> filters = filterChain.getWebFilters().toStream()
        AuthenticationWebFilter webFilter = filters
            .filter { (it.getClass().name == AuthenticationWebFilter.name) }
            .map {(AuthenticationWebFilter) it}
            .findFirst()
            .orElseThrow { new TestException("Failed to find BearerTokenAuthenticationWebFilter configured for JWTs, this could be caused by a configuration error, or a change in Spring Security (internal APIs are used to discover this WebFilter)")}
        ReactiveAuthenticationManagerResolver<?> authenticationManagerResolver = (ReactiveAuthenticationManagerResolver<?>) ReflectionTestUtils
            .getField(webFilter, "authenticationManagerResolver")
        Object authenticationManager = authenticationManagerResolver.resolve(null).block()
        assertThat(authenticationManager).isInstanceOf(JwtReactiveAuthenticationManager.class)
    }

     private static List<WebFilter> activeWebFilters(ApplicationContext context) {
         return context.getBean(WebFilterChainProxy).filters.stream()
                 .flatMap { it.getWebFilters().collectList().block().stream() }
                 .collect(Collectors.toList())
     }

    private static List<Class<WebFilter>> activeWebFiltersClasses(ApplicationContext context) {
        return activeWebFilters(context).stream()
                    .map { it.getClass() }
                    .collect(Collectors.toList())
    }

    private static List<Class<Filter>> activeFilters(ApplicationContext context) {
        FilterChainProxy filterChain = context.getBean("springSecurityFilterChain", FilterChainProxy)
        return filterChain.getFilterChains().stream()
                    .flatMap { chain -> chain.getFilters().stream() }
                    .map { it.getClass() }
                    .collect(Collectors.toList())
    }

    private WebApplicationContextRunner webContextRunner(Class<?>... appClasses = [SimpleWebApp]) {
        Class[] autoConfigs = [oktaAutoConfigs, appClasses].flatten()
        WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(autoConfigs))

        return withOktaProperties(contextRunner)
                .withInitializer(new ConditionEvaluationReportLoggingListener())
    }

    private reactiveContextRunner(Class<?>... appClasses = [SimpleReactiveApp]) {

        Class[] autoConfigs = [oktaAutoConfigs, appClasses].flatten()
        ReactiveWebApplicationContextRunner contextRunner = new ReactiveWebApplicationContextRunner(
        new Supplier<AnnotationConfigReactiveWebApplicationContext>() {
            @Override
            AnnotationConfigReactiveWebApplicationContext get() {
                return new AnnotationConfigReactiveWebApplicationContext() {
                    @Override
                    protected ConfigurableEnvironment createEnvironment() {
                        def configurableEnv = super.createEnvironment()
                        new OktaOAuth2PropertiesMappingEnvironmentPostProcessor().postProcessEnvironment(configurableEnv, null)
                        return configurableEnv
                    }
                }
            }
        })

        return contextRunner
                .withConfiguration(AutoConfigurations.of(autoConfigs))
                .withInitializer(new ConditionEvaluationReportLoggingListener())
    }

    private static <T extends AbstractApplicationContextRunner> T withOktaProperties(T contextRunner) {

        return (T) contextRunner.withInitializer(new OktaPropertiesContextInitializer())
    }

    static class OktaPropertiesContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
        @Override
        void initialize(ConfigurableApplicationContext applicationContext) {
            new OktaOAuth2PropertiesMappingEnvironmentPostProcessor().postProcessEnvironment(applicationContext.getEnvironment(), null)
        }
    }

    @Configuration
    @EnableWebSecurity
    static class SimpleWebApp {}

    @Configuration
    @EnableWebSecurity
    static class JwtResourceServerConfiguredApp {

        @Bean
        SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http.oauth2ResourceServer().jwt()
            return http.build()
        }
    }

    @Configuration
    @EnableWebSecurity
    static class OpaqueTokenResourceServerConfiguredApp {

        @Bean
        SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http.oauth2ResourceServer().opaqueToken()
            return http.build()
        }
    }

    @Configuration
    @EnableWebSecurity
    static class JwtAndOpaqueTokenResourceServerConfiguredApp {

        @Bean
        SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http.oauth2ResourceServer().jwt().and().opaqueToken()
            return http.build()
        }
    }

    @Configuration
    @EnableWebFluxSecurity
    static class SimpleReactiveApp {}

    @Configuration
    @EnableWebSecurity
    static class OverrideWebOidcComponents {

        @Bean
        OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() { // name is important here
            return new DefaultOAuth2UserService()
        }

        @Bean
        OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() { // name is important here
            return new OidcUserService()
        }
    }

    @Configuration
    @EnableWebFluxSecurity
    static class OverrideReactiveOidcComponents {

        @Bean
        ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
            return new DefaultReactiveOAuth2UserService()
        }

        @Bean
        OidcReactiveOAuth2UserService oidcUserService() {
            return new OidcReactiveOAuth2UserService()
        }
    }
}