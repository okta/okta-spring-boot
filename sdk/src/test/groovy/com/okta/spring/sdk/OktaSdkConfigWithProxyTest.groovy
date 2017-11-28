/*
 * Copyright 2017 Okta, Inc.
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
package com.okta.spring.sdk

import com.okta.sdk.client.Proxy
import com.okta.spring.config.OktaClientProperties
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class OktaSdkConfigWithProxyTest {

    @Test
    void proxyConfig() {
        OktaClientProperties clientProperties = new OktaClientProperties()
        clientProperties.setOrgUrl("https://okta.example.com")
        OktaSdkConfig config = new OktaSdkConfig(clientProperties, null)
        assertThat config.oktaSdkProxy(), nullValue()

        // just host
        clientProperties.proxy.hostname = "http://proxy.example.com"
        Proxy proxy = config.oktaSdkProxy()
        assertThat proxy, notNullValue()
        assertThat proxy.host, equalTo("http://proxy.example.com")
        assertThat proxy.port, equalTo(0)
        assertThat proxy.username, nullValue()
        assertThat proxy.password, nullValue()

        // host and port
        clientProperties.proxy.port = 9999
        proxy = config.oktaSdkProxy()
        assertThat proxy, notNullValue()
        assertThat proxy.host, equalTo("http://proxy.example.com")
        assertThat proxy.port, equalTo(9999)
        assertThat proxy.username, nullValue()
        assertThat proxy.password, nullValue()

        // just port
        clientProperties.proxy.hostname = null
        clientProperties.proxy.port = 9999
        proxy = config.oktaSdkProxy()
        assertThat config.oktaSdkProxy(), nullValue()

        // host, port, username
        clientProperties.proxy.hostname = "http://proxy.example.com"
        clientProperties.proxy.port = 9999
        clientProperties.proxy.username = "proxy-user"
        proxy = config.oktaSdkProxy()
        assertThat proxy, notNullValue()
        assertThat proxy.host, equalTo("http://proxy.example.com")
        assertThat proxy.port, equalTo(9999)
        assertThat proxy.username, equalTo("proxy-user")
        assertThat proxy.password, nullValue()

        // host, port, username, password
        clientProperties.proxy.password = "proxy-pass"
        proxy = config.oktaSdkProxy()
        assertThat proxy, notNullValue()
        assertThat proxy.host, equalTo("http://proxy.example.com")
        assertThat proxy.port, equalTo(9999)
        assertThat proxy.username, equalTo("proxy-user")
        assertThat proxy.password, equalTo("proxy-pass")

        // host, port, password
        clientProperties.proxy.username = null
        proxy = config.oktaSdkProxy()
        assertThat proxy, notNullValue()
        assertThat proxy.host, equalTo("http://proxy.example.com")
        assertThat proxy.port, equalTo(9999)
        assertThat proxy.username, nullValue()
        assertThat proxy.password, equalTo("proxy-pass")
    }
}
