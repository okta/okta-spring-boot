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
package com.okta.spring.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ExampleApplication {

//    @Bean
//    protected GlobalMethodSecurityConfiguration methodSecurityConfiguration() {
//        return new GlobalMethodSecurityConfiguration() {
//            @Override
//            protected MethodSecurityExpressionHandler createExpressionHandler() {
//                return new OAuth2MethodSecurityExpressionHandler();
//            }
//        };
//    }

    @Bean
    protected WebSecurityConfigurerAdapter webSecurityConfigurerAdapter() {
        return new WebSecurityConfigurerAdapter() {
            @Override
            public void configure(WebSecurity web) throws Exception {
                // allow access to the index page and our custom sign-in-widget-config
                web.ignoring().antMatchers("/", "/index.html", "/sign-in-widget-config");
            }
        };
    }

    public static void main(String[] args) {
        SpringApplication.run(ExampleApplication.class, args);
    }
}
