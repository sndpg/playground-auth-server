package org.psc.playground.auth.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "playground.auth")
public class PlaygroundAuthServerProperties {

    /**
     * OAuth2 client-id
     */
    private String clientId;

    /**
     * OAuth2 client-secret
     */
    private String clientSecret;

    /**
     * OAuth2 redirect uris
     */
    private String redirectUris;

}
