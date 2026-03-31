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
package com.okta.spring.boot.oauth;

import org.springframework.context.annotation.Conditional;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Activates when any of the following is present:
 * {@code okta.oauth2.issuer}, {@code spring.security.oauth2.resourceserver.jwt.issuer-uri},
 * or {@code spring.security.oauth2.resourceserver.jwt.jwk-set-uri}.
 *
 * <p>The OR semantics ensure that the resource-server beans are included in
 * GraalVM native images even when the OIDC discovery HTTP call cannot be made
 * at AOT compile time (fixes #406).</p>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.METHOD })
@Conditional(OktaResourceServerCondition.class)
@interface ConditionalOnOktaResourceServerProperties {}
