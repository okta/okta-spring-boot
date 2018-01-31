Run the example:
``` bash
mvn spring-boot:run \
 -Dokta.oauth2.issuer=https://{yourOktaDomain}/oauth2/{yourAuthorizationServerId} \
 -Dokta.oauth2.audience={yourAuthorizationServerAudience} \
 -Dokta.oauth2.clientId={oauthClientId} \
 -Dokta.oauth2.rolesClaim={customRoleClaim) # defaults to 'groups'
```

Browse to: http://localhost:8080
