package org.example.keycloak.browsersession;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public final class SsoResourceProviderFactory implements RealmResourceProviderFactory {
    private int challengeTtl;

    @Override
    public String getId() {
        return "sso";
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new RealmResourceProvider() {
            @Override
            public Object getResource() {
                return new SsoResource(session, challengeTtl);
            }

            @Override
            public void close() {
            }
        };
    }

    @Override
    public void init(Config.Scope config) {
        challengeTtl = config.getInt("challenge-ttl", 60);
        if (challengeTtl <= 0) {
            throw new IllegalArgumentException("SSO challenge-ttl must be positive");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
