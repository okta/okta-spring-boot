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
package com.okta.spring.boot.oauth;

import com.okta.commons.lang.ApplicationInfo;
import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.stream.Collectors;

final class WebClientUtil {

    private static final String USER_AGENT_VALUE = ApplicationInfo.get().entrySet().stream()
            .map(e -> e.getKey() + "/" + e.getValue())
            .collect(Collectors.joining(" "));

    private WebClientUtil() {}

    static WebClient createWebClient() {
       return WebClient.builder()
            .defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT_VALUE)
            .build();
    }
}
