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
package com.okta.spring.oauth.code.mvc;

import com.okta.spring.oauth.OktaOAuthProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class LoginController {

    private static final String STATE = "state";
    private static final String NONCE = "nonce";
    private static final String SCOPES = "scopes";
    private static final String OKTA_BASE_URL = "oktaBaseUrl";
    private static final String OKTA_CLIENT_ID = "oktaClientId";
    private static final String REDIRECT_URI = "redirectUri";
    private static final String ISSUER_URI = "issuerUri";
    private static final String WIDGET_CONFIG_MAP = "extraWidgetConfigMap";

    @Autowired
    private OktaOAuthProperties oktaOAuthProperties;

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    // FIXME: figure out what is going on with the nonce
    public ModelAndView login(@RequestParam("state") String state, @RequestParam(value = "nonce", required = false) String nonce) {
        ModelAndView mav = new ModelAndView("okta/login");
        mav.addObject(STATE, state);
        mav.addObject(NONCE, nonce);
        mav.addObject(SCOPES, oktaOAuthProperties.getOauth2().getScopes());
        mav.addObject(OKTA_BASE_URL, oktaOAuthProperties.getClient().getOrgUrl());
        mav.addObject(OKTA_CLIENT_ID, oktaOAuthProperties.getOauth2().getClientId());
        mav.addObject(REDIRECT_URI, oktaOAuthProperties.getOauth2().getRedirectUri());
        mav.addObject(ISSUER_URI, oktaOAuthProperties.getOauth2().getIssuer());
        mav.addObject(WIDGET_CONFIG_MAP, oktaOAuthProperties.getExtraWidgetConfig());
        return mav;
    }
}
