package com.kaiabit.keycloak.pwned;

import com.google.auto.service.AutoService;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;

import java.time.Duration;

@AutoService(PasswordPolicyProviderFactory.class)
public class PwnedPasswordPolicyFactory implements PasswordPolicyProviderFactory {
    private final Cache<String, Integer> kCache = CacheBuilder.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(Duration.ofHours(1))
            .build();

    @Override
    public String getDisplayName() {
        return "Not Pwned Password";
    }

    @Override
    public String getConfigType() {
        return null;
    }

    @Override
    public String getDefaultConfigValue() {
        return null;
    }

    @Override
    public boolean isMultiplSupported() {
        return false;
    }

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        return new PwnedPasswordPolicy(session, kCache);
    }


    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "notPwned";
    }
}
