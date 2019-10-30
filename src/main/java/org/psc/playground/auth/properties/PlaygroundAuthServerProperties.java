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

    /**
     * Path to keystore.jks
     */
    private String keyStorePath;

    /**
     * Password for keystore.jks
     */
    private String keyStorePassword;

    /**
     * Alias for self-signed key pair within the keyStore (selfsigned when generating with command from
     * generatingCertificate_README.txt.
     */
    private String keyPairAlias;

    /**
     * Password for key pair (same as keyStorePassword, if not changed manually).
     */
    private String keyPairPassword;

}
