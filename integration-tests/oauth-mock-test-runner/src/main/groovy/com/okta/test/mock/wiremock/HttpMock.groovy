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
package com.okta.test.mock.wiremock

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.common.ClasspathFileSource
import com.github.tomakehurst.wiremock.common.FileSource
import com.github.tomakehurst.wiremock.extension.Parameters
import com.github.tomakehurst.wiremock.extension.ResponseTransformer
import com.github.tomakehurst.wiremock.http.Request
import com.github.tomakehurst.wiremock.http.Response
import com.okta.test.mock.scenarios.Scenario
import com.okta.test.mock.scenarios.ScenarioDefinition
import groovy.text.StreamingTemplateEngine
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.testng.annotations.AfterClass
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig

abstract class HttpMock {

    final private Logger logger = LoggerFactory.getLogger(HttpMock)

    private WireMockServer wireMockServer
    private int port
    private String scenario

    void setScenario(String scenario) {
        this.scenario = scenario
    }

    Map getBaseBindingMap() {
        return Collections.unmodifiableMap([
            baseUrl: getBaseUrl()
        ])
    }

    void startMockServer() {
        if (wireMockServer == null) {

            ScenarioDefinition definition =  Scenario.fromId(scenario).definition
            Map bindingMap = baseBindingMap + definition.bindingMap

            wireMockServer = new WireMockServer(wireMockConfig()
                    .port(getMockPort())
                    .fileSource(new ClasspathFileSource("stubs"))
                    .extensions(new GStringTransformer(bindingMap))
            )

            definition.configureHttpMock(wireMockServer)
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

    abstract int doGetMockPort()

    String getBaseUrl() {
        return "http://localhost:${getMockPort()}"
    }
}

class GStringTransformer extends ResponseTransformer {

    private final Map binding

    GStringTransformer(Map binding) {
        this.binding = binding
    }

    @Override
    boolean applyGlobally() {
        return false
    }

    @Override
    Response transform(Request request, Response response, FileSource files, Parameters parameters) {
        Map params = (parameters == null) ? binding : binding + parameters
        return Response.Builder
                .like(response)
                .body(new StreamingTemplateEngine().createTemplate(response.bodyAsString).make(params).toString())
                .build()
    }

    @Override
    String getName() {
        return "gstring-template"
    }
}