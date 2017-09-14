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
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;


@SpringBootApplication
@EnableOAuth2Client
public class HostedLoginCodeFlowExampleApplication {

    /**
     * Enable OAuth claim checking from @PreAuthorize annotation.
     * @see com.okta.spring.example.resources.WelcomeResource
     */
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    protected static class GlobalSecurityConfiguration extends GlobalMethodSecurityConfiguration {
        @Override
        protected MethodSecurityExpressionHandler createExpressionHandler() {
            return new OAuth2MethodSecurityExpressionHandler();
        }
    }


    public static void main(String[] args) {
        SpringApplication.run(HostedLoginCodeFlowExampleApplication.class, args);
    }

//
//    @Configuration
//    public static class WebMvcConfig extends WebMvcConfigurerAdapter {
//
//        @Value("#{ @environment['okta.web.head.cssUris'] ?: '' }")
//        protected String headCssUris;
//
//        @Value("#{ @environment['okta.web.head.extraCssUris'] }")
//        protected String headExtraCssUris;
//
//        @Value("#{ @environment['okta.web.head.view'] ?: 'okta/head' }")
//        protected String headView;
//
//        @Value("#{ @environment['okta.web.head.fragmentSelector'] ?: 'head' }")
//        protected String headFragmentSelector;
//
//        @Autowired
//        private OktaOAuthProperties oktaOAuthProperties;
//
//        @Override
//        public void addInterceptors(InterceptorRegistry registry) {
//
//            registry.addInterceptor(oktaLayoutInterceptor());
//        }
//
//        @Bean
//        public HandlerInterceptor oktaLayoutInterceptor() {
//            TemplateLayoutInterceptor interceptor = new TemplateLayoutInterceptor();
//            interceptor.setHeadViewName(headView);
//            interceptor.setHeadFragmentSelector(headFragmentSelector);
//            interceptor.setOktaBaseUrl(oktaOAuthProperties.getBaseUrl());
//            interceptor.setOktaClientId(oktaOAuthProperties.getClient().getClientId());
//            interceptor.setRedirectUri(oktaOAuthProperties.getRedirectUri());
//            interceptor.setIssuerUri(oktaOAuthProperties.getIssuer());
//
//            //deal w/ URIs:
//            String[] uris = StringUtils.tokenizeToStringArray(headCssUris, " \t");
//            Set<String> uriSet = new LinkedHashSet<>();
//            if (uris != null && uris.length > 0) {
//                java.util.Collections.addAll(uriSet, uris);
//            }
//
//            uris = StringUtils.tokenizeToStringArray(headExtraCssUris, " \t");
//            if (uris != null && uris.length > 0) {
//                java.util.Collections.addAll(uriSet, uris);
//            }
//
//            if (!CollectionUtils.isEmpty(uriSet)) {
//                List<String> list = new ArrayList<>();
//                list.addAll(uriSet);
//                interceptor.setHeadCssUris(list);
//            }
//
//            try {
//                interceptor.afterPropertiesSet();
//            } catch (Exception e) {
//                String msg = "Unable to initialize stormpathLayoutInterceptor: " + e.getMessage();
//                throw new BeanInitializationException(msg, e);
//            }
//
//            return interceptor;
//        }
//    }

}
