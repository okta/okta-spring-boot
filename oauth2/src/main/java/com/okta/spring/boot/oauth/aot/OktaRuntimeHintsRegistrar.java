/*
 * Copyright 2022-Present Okta, Inc.
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
package com.okta.spring.boot.oauth.aot;

import com.okta.spring.boot.oauth.AuthoritiesProvider;
import com.okta.spring.boot.oauth.config.OktaOAuth2Properties;
import com.okta.spring.boot.oauth.env.OIDCMetadata;
import com.okta.spring.boot.oauth.env.OktaEnvironmentPostProcessorApplicationListener;
import com.okta.spring.boot.oauth.env.OktaOAuth2PropertiesMappingEnvironmentPostProcessor;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;

/**
 * GraalVM native image hints for Okta Spring Boot Starter classes.
 * Fixes https://github.com/okta/okta-spring-boot/issues/406
 *
 * @since 3.1.1
 */
public class OktaRuntimeHintsRegistrar implements RuntimeHintsRegistrar {

    @Override
    public void registerHints(RuntimeHints hints, ClassLoader classLoader) {

        // Register all Okta auto-configuration and property-source classes for reflection
        hints.reflection().registerTypes(
            java.util.List.of(
                TypeReference.of(OktaOAuth2Properties.class),
                TypeReference.of(OktaOAuth2Properties.Proxy.class),
                TypeReference.of(OIDCMetadata.class),
                TypeReference.of("com.okta.spring.boot.oauth.env.RemappedPropertySource"),
                TypeReference.of(OktaEnvironmentPostProcessorApplicationListener.class),
                TypeReference.of(OktaOAuth2PropertiesMappingEnvironmentPostProcessor.class),
                TypeReference.of("com.okta.spring.boot.oauth.OktaJwtAuthenticationConverter"),
                TypeReference.of(AuthoritiesProvider.class),
                TypeReference.of("com.okta.spring.boot.oauth.OktaResourceServerCondition"),
                TypeReference.of("com.okta.spring.boot.oauth.OktaOAuth2AutoConfig"),
                TypeReference.of("com.okta.spring.boot.oauth.OktaOAuth2ResourceServerAutoConfig"),
                TypeReference.of("com.okta.spring.boot.oauth.ReactiveOktaOAuth2AutoConfig"),
                TypeReference.of("com.okta.spring.boot.oauth.ReactiveOktaOAuth2ResourceServerAutoConfig"),
                TypeReference.of("com.okta.spring.boot.oauth.ReactiveOktaOAuth2ResourceServerHttpServerAutoConfig"),
                TypeReference.of("com.okta.spring.boot.oauth.ReactiveOktaOAuth2ServerHttpServerAutoConfig")
            ),
            hint -> hint.withMembers(
                MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                MemberCategory.INVOKE_PUBLIC_METHODS,
                MemberCategory.ACCESS_DECLARED_FIELDS
            )
        );

        // Register environment post-processors registered via spring.factories
        hints.reflection().registerType(
            TypeReference.of(OktaOAuth2PropertiesMappingEnvironmentPostProcessor.class),
            hint -> hint.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS, MemberCategory.INVOKE_PUBLIC_METHODS)
        );

        // Register resources needed at runtime
        hints.resources().registerPattern("META-INF/okta/version.properties");
        hints.resources().registerPattern("com/okta/spring/oauth/version.properties");
        hints.resources().registerPattern("META-INF/spring.factories");
        hints.resources().registerPattern("META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports");
        hints.resources().registerPattern("META-INF/spring/org.springframework.aot.hint.RuntimeHintsRegistrar");

        // Allow dynamic property source creation (used by RemappedPropertySource, ConditionalMapPropertySource, etc.)
        hints.reflection().registerType(
            TypeReference.of(org.springframework.core.env.MapPropertySource.class),
            hint -> hint.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS, MemberCategory.INVOKE_PUBLIC_METHODS)
        );
    }
}
