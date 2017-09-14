/*
 * Copyright 2015 Stormpath, Inc.
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

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

/**
 */
public class TemplateLayoutInterceptor extends HandlerInterceptorAdapter implements InitializingBean {

    public static final String HEAD_VIEW_NAME_KEY = "headViewName";
    public static final String HEAD_FRAGMENT_SELECTOR_KEY = "headFragmentSelector";
    public static final String HEAD_CSS_URIS_KEY = "headCssUris";


    private String headViewName;
    private String headFragmentSelector;
    private List<String> headCssUris;

    public String getHeadViewName() {
        return headViewName;
    }

    public void setHeadViewName(String headViewName) {
        this.headViewName = headViewName;
    }

    public String getHeadFragmentSelector() {
        return headFragmentSelector;
    }

    public void setHeadFragmentSelector(String headFragmentSelector) {
        this.headFragmentSelector = headFragmentSelector;
    }

    public List<String> getHeadCssUris() {
        return headCssUris;
    }

    public void setHeadCssUris(List<String> headCssUris) {
        this.headCssUris = headCssUris;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.hasText(headViewName, "headViewName must be specified.");
    }

    protected boolean shouldExecute(HttpServletRequest request, HttpServletResponse response,
                                    Object handler, ModelAndView modelAndView) {

        if (modelAndView == null || !modelAndView.isReference() /*|| STORMPATH_JSON_VIEW_NAME.equals(modelAndView.getViewName()) */) {
            return false;
        }

        String viewName = modelAndView.getViewName();
        if (isRedirectOrForward(viewName)) {
            return false;
        }

        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           ModelAndView modelAndView) throws Exception {

        if (!shouldExecute(request, response, handler, modelAndView)) {
            return;
        }

        if (!modelAndView.getModel().containsKey(HEAD_VIEW_NAME_KEY)) {
            modelAndView.addObject(HEAD_VIEW_NAME_KEY, headViewName);
        }


        if (StringUtils.hasText(headFragmentSelector) && !modelAndView.getModel().containsKey(HEAD_FRAGMENT_SELECTOR_KEY)) {
            modelAndView.addObject(HEAD_FRAGMENT_SELECTOR_KEY, headFragmentSelector);
        }

        if (!CollectionUtils.isEmpty(headCssUris) && !modelAndView.getModel().containsKey(HEAD_CSS_URIS_KEY)) {

            List<String> modified = new ArrayList<String>(headCssUris.size());

            for(String uri : headCssUris) {
                if (uri.startsWith("http") || uri.startsWith("//")) {
                    modified.add(uri);
                } else {
                    //context relative, prefix it w/ the context path:
                    String contextPath = request.getContextPath();
                    String contextRelative = contextPath + uri;
                    modified.add(contextRelative);
                }
            }

            modelAndView.addObject(HEAD_CSS_URIS_KEY, modified);
        }
    }

    private boolean isRedirectOrForward(String viewName) {
        return viewName.startsWith("redirect:") || viewName.startsWith("forward:");
    }
}
