package com.okta.spring.boot.oauth.http;

import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.okta.commons.lang.ApplicationInfo;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

public final class Auth0RequestInterceptor implements ClientHttpRequestInterceptor {

    private static final String clientData;

    private static final String AUTH0_CLIENT_HEADER = "Auth0-Client";
    private static final String LIBRARY_NAME_KEY = "name";
    private static final String LIBRARY_NAME = "okta-spring-security";
    private static final String VERSION_KEY = "version";
    private static final String JAVA_KEY = "java";
    private static final String SPRING_KEY = "spring";
    private static final String SPRING_BOOT_KEY = "spring-boot";
    private static final String SPRING_SECURITY_KEY = "spring-security";
    private static final String ENV_KEY = "env";

    static {
        ObjectMapper mapper = new ObjectMapper();

        Map<String, Object> appInfo = new HashMap<>();

        appInfo.put(LIBRARY_NAME_KEY, LIBRARY_NAME);
        appInfo.put(VERSION_KEY, ApplicationInfo.get().get(LIBRARY_NAME));

        Map<String, String> envData = new HashMap<>();
        envData.put(JAVA_KEY, ApplicationInfo.get().get(JAVA_KEY));
        envData.put(SPRING_KEY, ApplicationInfo.get().get(SPRING_KEY));
        envData.put(SPRING_BOOT_KEY, ApplicationInfo.get().get(SPRING_BOOT_KEY));
        envData.put(SPRING_SECURITY_KEY, ApplicationInfo.get().get(SPRING_SECURITY_KEY));

        appInfo.put(ENV_KEY, envData);

        String tempClientData;

        try {
            String json = mapper.writeValueAsString(appInfo);
            tempClientData = Base64.getUrlEncoder().encodeToString(json.getBytes());
        } catch (JsonProcessingException ignored) {
            tempClientData = "";
        }
        clientData = tempClientData;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        request.getHeaders().add(AUTH0_CLIENT_HEADER, clientData);
        return execution.execute(request, body);
    }
}
