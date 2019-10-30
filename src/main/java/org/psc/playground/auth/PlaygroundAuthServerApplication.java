package org.psc.playground.auth;

import org.psc.playground.auth.properties.PlaygroundAuthServerProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@EnableAuthorizationServer
@SpringBootApplication
@EnableConfigurationProperties(PlaygroundAuthServerProperties.class)
public class PlaygroundAuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(PlaygroundAuthServerApplication.class, args);
    }

}
