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
package com.okta.spring.example.wiremock

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.common.ClasspathFileSource
import com.github.tomakehurst.wiremock.common.FileSource
import com.github.tomakehurst.wiremock.extension.Parameters
import com.github.tomakehurst.wiremock.extension.ResponseTransformer
import com.github.tomakehurst.wiremock.http.Request
import com.github.tomakehurst.wiremock.http.Response
import groovy.text.StreamingTemplateEngine
import org.testng.annotations.AfterClass
import org.testng.annotations.AfterMethod
import org.testng.annotations.BeforeClass
import org.testng.annotations.BeforeMethod

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig

trait HttpMock {

    private WireMockServer wireMockServer
    private int port

    Map getBindingMap() {
        return [baseUrl: getBaseUrl()]
    }

    @BeforeClass
    void startMockServer() {
        if (wireMockServer == null) {
            wireMockServer = new WireMockServer(wireMockConfig()
                    .port(getMockPort())
                    .fileSource(new ClasspathFileSource("stubs"))
                    .extensions(new GStringTransformer(getBindingMap()))
            )

            configureHttpMock(wireMockServer)
            wireMockServer.start()
        }
    }

    @AfterClass
    void stopMockServer() {
        if (wireMockServer != null) {
            wireMockServer.stop()
        }
    }

    int getMockPort() {
        if (port == 0) {
            port = doGetMockPort()
        }
        return port
    }

    int doGetMockPort() {
        int port = new ServerSocket(0).withCloseable {it.getLocalPort()}
        return port
    }

    String getBaseUrl() {
        return "http://localhost:${getMockPort()}"
    }

    abstract void configureHttpMock(WireMockServer wireMockServer)
}

class GStringTransformer extends ResponseTransformer {

    private final Map binding

    GStringTransformer(Map binding) {
        this.binding = binding
    }

    @Override
    Response transform(Request request, Response response, FileSource files, Parameters parameters) {
        return Response.Builder
                .like(response)
                .body(new StreamingTemplateEngine().createTemplate(response.bodyAsString).make(binding).toString())
                .build()
    }

    @Override
    String getName() {
        return "gstring-template"
    }
}


