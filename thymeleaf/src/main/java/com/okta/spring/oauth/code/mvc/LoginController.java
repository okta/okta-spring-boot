package com.okta.spring.oauth.code.mvc;

import com.okta.spring.oauth.OktaOAuthProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
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

    @RequestMapping("/login")
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
