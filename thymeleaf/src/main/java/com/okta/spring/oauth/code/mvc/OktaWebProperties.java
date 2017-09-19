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

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("okta.web")
public class OktaWebProperties {

    private HeadProperties head = new HeadProperties();

    private String logo = "https://ok1static.oktacdn.com/assets/img/logos/okta-logo.png";

    public HeadProperties getHead() {
        return head;
    }

    public void setHead(HeadProperties head) {
        this.head = head;
    }

    public String getLogo() {
        return logo;
    }

    public void setLogo(String logo) {
        this.logo = logo;
    }

    public static class HeadProperties {

        private String cssUris = "/okta/okta.css";

        private String extraCssUris;

        private String view = "okta/head";

        private String fragmentSelector = "head";

        public String getCssUris() {
            return cssUris;
        }

        public void setCssUris(String cssUris) {
            this.cssUris = cssUris;
        }

        public String getExtraCssUris() {
            return extraCssUris;
        }

        public void setExtraCssUris(String extraCssUris) {
            this.extraCssUris = extraCssUris;
        }

        public String getView() {
            return view;
        }

        public void setView(String view) {
            this.view = view;
        }

        public String getFragmentSelector() {
            return fragmentSelector;
        }

        public void setFragmentSelector(String fragmentSelector) {
            this.fragmentSelector = fragmentSelector;
        }
    }

}
