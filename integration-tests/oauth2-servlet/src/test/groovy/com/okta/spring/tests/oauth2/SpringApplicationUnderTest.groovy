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
package com.okta.spring.tests.oauth2

import com.okta.test.mock.application.ApplicationUnderTest
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.boot.SpringApplication
import org.springframework.context.ConfigurableApplicationContext

class SpringApplicationUnderTest implements ApplicationUnderTest {

    private final Logger logger = LoggerFactory.getLogger(SpringApplicationUnderTest)

    private ConfigurableApplicationContext applicationContext

    @Override
    void start() {

        testScenario.args.stream()
                .filter {it.startsWith("-D")}
                .map {it.substring(2)}
                .map {it.split("=")}
                .forEach {
            System.setProperty(it[0], it[1])
        }

        applicationContext = SpringApplication.run(
                Class.forName(testScenario.command),
                testScenario.args.toArray(new String[testScenario.args.size()]))
    }

    @Override
    int stop() {

        if (applicationContext != null && applicationContext.isRunning()) {
            applicationContext.stop()
            return 0
        } else {
            logger.warn("Spring Application was not running")
            return 1
        }
    }
}
