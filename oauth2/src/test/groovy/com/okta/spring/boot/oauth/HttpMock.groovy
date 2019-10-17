/*
 * Copyright 2019-Present Okta, Inc.
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

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import org.testng.annotations.AfterClass
import org.testng.annotations.BeforeClass

trait HttpMock {

    private WireMockServer wireMockServer = null
    private httpPort = getFreePort()

    @BeforeClass
    void start() {
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(httpPort))
        configureHttpMock(wireMockServer)
        wireMockServer.start()
    }

    @AfterClass
    void stop() {
        if (wireMockServer != null) {
            wireMockServer.stop()
        }
    }

    String mockBaseUrl() {
        return "http://localhost:${httpPort}/"
    }

    int getFreePort() {
        int port = new ServerSocket(0).withCloseable {it.getLocalPort()}
        return port
    }

    abstract void configureHttpMock(WireMockServer wireMockServer)
}