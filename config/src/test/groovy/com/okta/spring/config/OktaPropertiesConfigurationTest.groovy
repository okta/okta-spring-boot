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
package com.okta.spring.config

import org.springframework.beans.factory.BeanCreationException
import org.springframework.boot.test.util.EnvironmentTestUtils
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.testng.Assert
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.allOf
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.instanceOf

class OktaPropertiesConfigurationTest {

    @Test
    void issuerIsNotAUrl() {
        createAndValidateContext({
            assertThat(it.message, allOf(containsString("foobar"),
                                         containsString("It looks like there's a typo in your Okta Issuer URL")))
        }, "okta.oauth2.issuer:foobar")
    }

    @Test
    void nonHttpsIssuerUrl() {
        createAndValidateContext({
            assertThat(it.message, allOf(containsString("http://okta.example.com"),
                                         containsString("Your Okta Issuer URL must start with https")))
        }, "okta.oauth2.issuer:http://okta.example.com")
    }

    static void createAndValidateContext(Closure<BeanCreationException> validation, String... pairs) {

        def context = new AnnotationConfigApplicationContext()
        context.register(OktaPropertiesConfiguration.class)
        try {
            EnvironmentTestUtils.addEnvironment(context, pairs)
            def e = expect(BeanCreationException, {context.refresh()})
            validation.call(e)
        } finally {
            context.close()
        }
    }

    static <E extends Throwable> E expect(Class<E> catchMe, Closure callMe) {
        try {
            callMe.call()
            Assert.fail("Expected ${catchMe.getName()} to be thrown.")
        } catch(e) {
            assertThat(e, instanceOf(catchMe))
            return e
        }
    }
}
