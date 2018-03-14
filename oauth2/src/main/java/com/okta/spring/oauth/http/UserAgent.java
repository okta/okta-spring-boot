/*
 * Copyright 2014 Stormpath, Inc.
 * Modifications Copyright 2018 Okta, Inc.
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
package com.okta.spring.oauth.http;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * This class is in charge of constructing the <a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.43">
 * User-Agent http header</a> string that will be sent to Okta in order to describe the current running environment of this Java SDK.
 * <p>
 * The form of this string is the concatenation of the following sub-items:
 * <ol>
 *     <li>The okta integration and version separated by a '/'.  If there is no integration being used, this can be omitted
 *     <li>The okta sdk and version separated by a '/'
 *     <li>The runtime information (runtime/version)
 *     <ol type="a">
 *          <li>Integration Runtime (if there is no integration being used, this can be omitted)
 *          <li>SDK Runtime
 *     </ol>
 *     <li>The OS common name and version separated by a '/'.
 *     <li>All other system information included in parentheses
 * </ol>
 * <p>
 * The User-Agent value is created when this class is loaded. The string can be obtained just by invoking
 * {@link UserAgent#getUserAgentString() UserAgent.getUserAgentString()}.
 * <p>
 * This is a sample User-Agent string:
 * <i>okta-spring-security/0.7.0 okta-sdk-java/0.5.0 spring/4.0.4.RELEASE java/1.7.0_45 Mac OS X/10.9.2 (spring-security/3.2.0.RELEASE jetty/8.1.5.v20120716)</i>
 *
 * @since 0.4.0
 */
public class UserAgent {

    private static final Logger LOG = LoggerFactory.getLogger(UserAgent.class);

    //Integrations (aka Plugins)
    private static final String INTEGRATION_SHIRO_ID = "okta-shiro";
    private static final String INTEGRATION_SHIRO_CLASS = "com.okta.shiro.realm.ApplicationRealm";
    private static final String INTEGRATION_SPRING_SECURITY_ID = "okta-spring-security";

    //SDK
    private static final String SDK_VERSION_FILE = "/com/okta/sdk/version.properties";
    private static final String OKTA_SDK_STRING = "okta-sdk-java";
    private static final String OKTA_SDK_CLASS = "com.okta.sdk.resource.user.User";

    //Okta Zuul support
    private static final String OKTA_ZUUL_ID = "okta-zuul";
    private static final String OKTA_ZUUL_CLASS = "com.okta.zuul.filter.AppliedRequestHeaderFilter";

    //Okta Java Servlet Plugin
    private static final String OKTA_SDK_SERVLET_ID = "okta-servlet-java";
    private static final String OKTA_SDK_SERVLET_CLASS = "com.okta.sdk.servlet.config.Config";

    private static final String OKTA_SDK_RUNTIME_SPRING_WEBMVC_ID = "okta-spring-webmvc";
    private static final String OKTA_SDK_RUNTIME_SPRING_WEBMVC_CLASS = "com.okta.spring.mvc.AbstractSpringControllerConfig";

    //Okta Spring Boot
    private static final String OKTA_SDK_SPRING_BOOT_STARTER_ID = "okta-spring-boot-starter";
    private static final String OKTA_SDK_SPRING_BOOT_STARTER_CLASS = "com.okta.spring.boot.autoconfigure.OktaAutoConfiguration";

    //Integration Runtimes
    private static final String INTEGRATION_RUNTIME_SPRING_ID = "spring";
    private static final String INTEGRATION_RUNTIME_SPRING_CLASS = "org.springframework.context.ApplicationContext";

    //Rapid Prototyping
    private static final String RAPID_PROTOTYPING_SPRING_BOOT_ID = "spring-boot";
    private static final String RAPID_PROTOTYPING_SPRING_BOOT_CLASS = "org.springframework.boot.SpringApplication";

    //Runtime
    private static final String JAVA_SDK_RUNTIME_STRING = "java";

    ////Additional Information////

    //Security Frameworks
    private static final String SECURITY_FRAMEWORK_SHIRO_ID = "shiro";
    private static final String SECURITY_FRAMEWORK_SHIRO_CLASS = "org.apache.shiro.SecurityUtils";
    private static final String SECURITY_FRAMEWORK_SPRING_SECURITY_ID = "spring-security";
    private static final String SECURITY_FRAMEWORK_SPRING_SECURITY_CLASS = "org.springframework.security.core.SpringSecurityCoreVersion";

    //Web Servers
    private static final String WEB_SERVER_TOMCAT_ID = "tomcat";
    private static final String WEB_SERVER_TOMCAT_BOOTSTRAP_CLASS = "org.apache.catalina.startup.Bootstrap";
    private static final String WEB_SERVER_TOMCAT_EMBEDDED_CLASS = "org.apache.catalina.startup.Tomcat";
    private static final String WEB_SERVER_JETTY_ID = "jetty";
    private static final String WEB_SERVER_JETTY_CLASS = "org.eclipse.jetty.servlet.listener.ELContextCleaner";
    private static final String WEB_SERVER_JBOSS_ID = "jboss";
    private static final String WEB_SERVER_JBOSS_CLASS = "org.jboss.as.security.plugins.AuthenticationCacheEvictionListener";
    private static final String WEB_SERVER_WEBSPHERE_ID = "websphere";
    private static final String WEB_SERVER_WEBSPHERE_CLASS = "com.ibm.websphere.product.VersionInfo";
    private static final String WEB_SERVER_GLASSFISH_ID = "glassfish";
    private static final String WEB_SERVER_GLASSFISH_CLASS = "com.sun.enterprise.glassfish.bootstrap.GlassFishMain";
    private static final String WEB_SERVER_WEBLOGIC_ID = "weblogic";
    private static final String WEB_SERVER_WEBLOGIC_CLASS = "weblogic.version";
    private static final String WEB_SERVER_WILDFLY_ID = "wildfly";
    private static final String WEB_SERVER_WILDFLY_CLASS = "org.jboss.as.security.ModuleName";

    private static final String VERSION_SEPARATOR = "/";
    private static final String ENTRY_SEPARATOR = " ";

    //Placeholder for the actual User-Agent String
    private static final String USER_AGENT = createUserAgentString();

    private UserAgent() {
    }

    public static String getUserAgentString() {
        return USER_AGENT;
    }

    private static String createUserAgentString() {
        String userAgent =
                getOktaSpringString() +                 // okta-spring-security
                getOktaShiroString() +                  // okta-shiro
                getOktaSDKComponentsString() +          // okta-servlet-java | okta-spring-boot-starter
                getOktaSdkString() +                    // okta-sdk-java
                getSecurityFrameworkString() +          // shiro | spring-security
                getIntegrationRuntimeString() +         // spring
                getSpringBootString() +                 // spring-boot
                getWebServerString() +                  // tomcat | jetty | jboss | websphere | glassfish | weblogic | wildfly
                getJavaSDKRuntimeString() +             // java
                getOSString();                          // Mac OS X
        return userAgent.trim();
    }

    private static String getOktaShiroString() {
        String integrationString;
        integrationString = getFullEntryStringUsingPomProperties(INTEGRATION_SHIRO_CLASS, INTEGRATION_SHIRO_ID);
        if (StringUtils.hasText(integrationString)) {
            return integrationString;
        }
        return "";
    }

    private static String getOktaSpringString() {
        return INTEGRATION_SPRING_SECURITY_ID + VERSION_SEPARATOR + Version.getClientVersion() + ENTRY_SEPARATOR;
    }

    private static String getOktaSdkString() {

        if (ClassUtils.isPresent(OKTA_SDK_CLASS, null)) {
            return OKTA_SDK_STRING + VERSION_SEPARATOR + Version.getClientVersion(SDK_VERSION_FILE) + ENTRY_SEPARATOR;
        }
        return "";
    }

    private static String getIntegrationRuntimeString() {
        String integrationRuntimeString;
        integrationRuntimeString = getFullEntryStringUsingManifest(INTEGRATION_RUNTIME_SPRING_CLASS, INTEGRATION_RUNTIME_SPRING_ID);
        if (StringUtils.hasText(integrationRuntimeString)) {
            return integrationRuntimeString;
        }
        return "";
    }

    private static String getJavaSDKRuntimeString() {
        return JAVA_SDK_RUNTIME_STRING + VERSION_SEPARATOR + System.getProperty("java.version") + ENTRY_SEPARATOR;
    }

    private static String getOSString() {
        return System.getProperty("os.name") + VERSION_SEPARATOR + System.getProperty("os.version") + ENTRY_SEPARATOR;
    }

    //Spring Boot
    private static String getSpringBootString() {
        String springBootStarter = getFullEntryStringUsingManifest(RAPID_PROTOTYPING_SPRING_BOOT_CLASS, RAPID_PROTOTYPING_SPRING_BOOT_ID);
        if (StringUtils.hasText(springBootStarter)) {
            return springBootStarter;
        }
        return "";
    }

    private static String getSecurityFrameworkString() {

        String securityFrameworkString;
        securityFrameworkString = getFullEntryStringUsingManifest(SECURITY_FRAMEWORK_SHIRO_CLASS, SECURITY_FRAMEWORK_SHIRO_ID);
        if (StringUtils.hasText(securityFrameworkString)) {
            return securityFrameworkString;
        }
        securityFrameworkString = getFullEntryStringUsingManifest(SECURITY_FRAMEWORK_SPRING_SECURITY_CLASS, SECURITY_FRAMEWORK_SPRING_SECURITY_ID);
        if (StringUtils.hasText(securityFrameworkString)) {
            return securityFrameworkString;
        }
        return "";
    }

    //Okta SDK Components
    private static String getOktaSDKComponentsString() {

        StringBuilder sb = new StringBuilder();

        append(sb, getFullEntryStringUsingSDKVersion(OKTA_ZUUL_CLASS, OKTA_ZUUL_ID));
        append(sb, getFullEntryStringUsingSDKVersion(OKTA_SDK_SERVLET_CLASS, OKTA_SDK_SERVLET_ID));
        append(sb, getFullEntryStringUsingSDKVersion(OKTA_SDK_RUNTIME_SPRING_WEBMVC_CLASS, OKTA_SDK_RUNTIME_SPRING_WEBMVC_ID));
        append(sb, getFullEntryStringUsingSDKVersion(OKTA_SDK_SPRING_BOOT_STARTER_CLASS, OKTA_SDK_SPRING_BOOT_STARTER_ID));

        return sb.toString();
    }

    private static void append(StringBuilder sb, String value) {
        if (StringUtils.hasText(value)) {
            sb.append(value);
        }
    }

    private static String getWebServerString() {
        String webServerString;
        //Glassfish uses Tomcat internally, therefore the Glassfish check must be carried out before Tomcat's
        webServerString = getFullEntryStringUsingManifest(WEB_SERVER_GLASSFISH_CLASS, WEB_SERVER_GLASSFISH_ID);
        if (StringUtils.hasText(webServerString)) {
            return webServerString;
        }
        webServerString = getFullEntryStringUsingManifest(WEB_SERVER_TOMCAT_BOOTSTRAP_CLASS, WEB_SERVER_TOMCAT_ID);
        if (StringUtils.hasText(webServerString)) {
            return webServerString;
        }
        webServerString = getFullEntryStringUsingManifest(WEB_SERVER_TOMCAT_EMBEDDED_CLASS, WEB_SERVER_TOMCAT_ID);
        if (StringUtils.hasText(webServerString)) {
            return webServerString;
        }
        webServerString = getFullEntryStringUsingManifest(WEB_SERVER_JETTY_CLASS, WEB_SERVER_JETTY_ID);
        if (StringUtils.hasText(webServerString)) {
            return webServerString;
        }
        //WildFly must be before JBoss
        webServerString = getWildFlyEntryString();
        if (StringUtils.hasText(webServerString)) {
            return webServerString;
        }
        webServerString = getFullEntryStringUsingManifest(WEB_SERVER_JBOSS_CLASS, WEB_SERVER_JBOSS_ID);
        if (StringUtils.hasText(webServerString)) {
            return webServerString;
        }
        webServerString = getWebSphereEntryString();
        if (StringUtils.hasText(webServerString)) {
            return webServerString;
        }
        webServerString = getWebLogicEntryString();
        if (StringUtils.hasText(webServerString)) {
            return webServerString;
        }

        return "";
    }

    private static String getFullEntryStringUsingPomProperties(String fqcn, String entryId) {
        if (ClassUtils.isPresent(fqcn, null)) {
            return entryId + VERSION_SEPARATOR + getVersionInfoFromPomProperties(fqcn) + ENTRY_SEPARATOR;
        }
        return null;
    }

    private static String getFullEntryStringUsingManifest(String fqcn, String entryId) {
        if (ClassUtils.isPresent(fqcn, null)) {
            return entryId + VERSION_SEPARATOR + getVersionInfoInManifest(fqcn) + ENTRY_SEPARATOR;
        }
        return null;
    }

    private static String getFullEntryStringUsingSDKVersion(String fqcn, String entryId) {
        if (ClassUtils.isPresent(fqcn, null)) {
            return entryId + VERSION_SEPARATOR + getVersionInfoInManifest(fqcn) + ENTRY_SEPARATOR;
        }
        return null;
    }

    private static String getWebSphereEntryString() {
        if (ClassUtils.isPresent(WEB_SERVER_WEBSPHERE_CLASS, null)) {
            return WEB_SERVER_WEBSPHERE_ID + VERSION_SEPARATOR + getWebSphereVersion() + ENTRY_SEPARATOR;
        }
        return null;
    }

    private static String getWebLogicEntryString() {
        if (ClassUtils.isPresent(WEB_SERVER_WEBLOGIC_CLASS, null)) {
            return WEB_SERVER_WEBLOGIC_ID + VERSION_SEPARATOR + getWebLogicVersion() + ENTRY_SEPARATOR;
        }
        return null;
    }

    private static String getWildFlyEntryString() {
        try {
            if (ClassUtils.isPresent(WEB_SERVER_WILDFLY_CLASS, null)) {
                Package wildFlyPkg = ClassUtils.forName(WEB_SERVER_WILDFLY_CLASS, null).getPackage();
                if (wildFlyPkg != null
                    && StringUtils.hasText(wildFlyPkg.getImplementationTitle()) && wildFlyPkg.getImplementationTitle().contains("WildFly")) {
                        return WEB_SERVER_WILDFLY_ID + VERSION_SEPARATOR + wildFlyPkg.getImplementationVersion() + ENTRY_SEPARATOR;
                }

            }

        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e){ //NOPMD
            //there was a problem obtaining the WildFly version
        }
        return null;
    }

    /**
     * WARNING: This method must never be invoked unless we already know that the class identified by the parameter {@code fqcn}
     * really exists in the classpath. For example, we first need to assure that {@code Classes.isAvailable(fqcn))} is <code>TRUE</code>
     */
    private static String getVersionInfoFromPomProperties(String fqcn) {
        String version = "unknown";
        try{
            Class clazz = ClassUtils.forName(fqcn, null);
            String className = clazz.getSimpleName() + ".class";
            String classPath = clazz.getResource(className).toString();

            String jarPath = null;
            if (classPath.startsWith("jar:file:")) {
                //Let's remove "jar:file:" from the beginning and also the className
                jarPath = classPath.subSequence(9, classPath.lastIndexOf("!")).toString();
            } else if (classPath.startsWith("vfs:")) {
                //Let's remove "vfs:" from the beginning and also the className
                jarPath = classPath.subSequence(4, classPath.lastIndexOf(".jar") + 4).toString();
            }

            if (jarPath == null) {
                //we were not able to obtain the jar path. Let's abort
                return version;
            }

            Enumeration<JarEntry> enumeration;
            String pomPropertiesPath;
            try (JarFile jarFile = new JarFile(jarPath)) {
                enumeration = jarFile.entries();
            }
            pomPropertiesPath = null;
            while (enumeration.hasMoreElements()) {
                JarEntry entry = enumeration.nextElement();
                if (entry.getName().endsWith("pom.properties")) {
                    pomPropertiesPath = entry.getName();
                    break;
                }
            }
            if (pomPropertiesPath != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(clazz.getResourceAsStream("/" + pomPropertiesPath), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.startsWith("version=")) {
                            version = line.split("=")[1];
                            break;
                        }
                    }
                }
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) { //NOPMD
            //Either the jar file or the internal "pom.properties" file could not be read, there is nothing we can do...
        }
        return version;
    }

    /**
     * WARNING: This method must never be invoked unless we already know that the class identified by the parameter {@code fqcn}
     * really exists in the classpath. For example, we first need to assure that {@code Classes.isAvailable(fqcn))} is <code>TRUE</code>
     */
    private static String getVersionInfoInManifest(String fqcn){
        String version = null;
        try {
            //get class package
            Package thePackage = ClassUtils.forName(fqcn, null).getPackage();
            //examine the package object
            version = thePackage.getSpecificationVersion();
            if (!StringUtils.hasText(version)) {
                version = thePackage.getImplementationVersion();
            }
        } catch (ClassNotFoundException e) {
            LOG.debug("Failed resolve version for class '{}'", fqcn, e);
        }

        if (!StringUtils.hasText(version)) {
            version = "null";
        }
        return version;
    }

    /**
     * This method should only be invoked after already knowing that the class identified by {@code WEB_SERVER_WEBSPHERE_CLASS}
     * really exists in the classpath. For example, it can be checked that {@code Classes.isAvailable(WEB_SERVER_WEBSPHERE_CLASS))}
     * is {@code TRUE}
     */
    private static String getWebSphereVersion() {
        try {
            Class<?> versionClass = Class.forName(WEB_SERVER_WEBSPHERE_CLASS);
            Object versionInfo = versionClass.newInstance();
            Method method = versionClass.getDeclaredMethod("runReport", String.class, PrintWriter.class);
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            method.invoke(versionInfo, "", printWriter);
            String version = stringWriter.toString();
            // version looks like this, so we need to "substring" it:
            //
            //
            //IBM WebSphere Product Installation Status Report
            //--------------------------------------------------------------------------------
            //
            //Report at date and time August 13, 2014 1:12:06 PM ART
            //
            //Installation
            //--------------------------------------------------------------------------------
            //Product Directory        C:\Program Files\IBM\WebSphere\AppServer
            //Version Directory        C:\Program Files\IBM\WebSphere\AppServer\properties\version
            //DTD Directory            C:\Program Files\IBM\WebSphere\AppServer\properties\version\dtd
            //Log Directory            C:\Documents and Settings\All Users\Application Data\IBM\Installation Manager\logs
            //
            //Product List
            //--------------------------------------------------------------------------------
            //BASETRIAL                installed
            //
            //Installed Product
            //--------------------------------------------------------------------------------
            //Name                  IBM WebSphere Application Server
            //Version               8.5.5.2
            //ID                    BASETRIAL
            //Build Level           cf021414.01
            //Build Date            4/8/14
            //Package               com.ibm.websphere.BASETRIAL.v85_8.5.5002.20140408_1947
            //Architecture          x86 (32 bit)
            //Installed Features    IBM 32-bit WebSphere SDK for Java
            //WebSphere Application Server Full Profile

            version = version.substring(version.indexOf("Installed Product"));
            version = version.substring(version.indexOf("Version"));
            version = version.substring(version.indexOf(" "), version.indexOf("\n")).trim();
            return version;

        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) { //NOPMD
            //there was a problem obtaining the WebSphere version
        }
        //returning null so we can identify in the User-Agent String that we are not properly handling some WebSphere version
        return "null";
    }

    /**
     * This method should only be invoked after already knowing that the class identified by {@code WEB_SERVER_WEBLOGIC_CLASS}
     * really exists in the classpath. For example, it can be checked that {@code Classes.isAvailable(WEB_SERVER_WEBLOGIC_CLASS))}
     * is {@code TRUE}
     */
    private static String getWebLogicVersion() {
        try {
            Class<?> versionClass = Class.forName(WEB_SERVER_WEBLOGIC_CLASS);
            Object version = versionClass.newInstance();
            Method method = versionClass.getDeclaredMethod("getReleaseBuildVersion");
            return (String) method.invoke(version);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) { //NOPMD
            //there was a problem obtaining the WebLogic version
        }
        //returning null so we can identify in the User-Agent String that we are not properly handling some WebLogic version
        return "null";
    }
}
