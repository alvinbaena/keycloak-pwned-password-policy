package com.kaiabit.keycloak.pwned;

import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;
import java.util.Scanner;

@JBossLog
@RequiredArgsConstructor
public class PwnedPasswordPolicy implements PasswordPolicyProvider {

    private final KeycloakSession session;
    private final Cache<String, Integer> kCache;

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        return validate(user.getUsername(), password);
    }

    @Override
    public PolicyError validate(String user, String password) {
        String hash = hash(password);
        Integer fromCache = kCache.getIfPresent(hash);
        if (!kCache.asMap().containsKey(hash)) {
            try {
                fromCache = callKAnonymity(hash, session);
            } catch (Exception e) {
                log.warn("Error calling k-anonymity", e);
                return null;
            }
        }
        if (Optional.ofNullable(fromCache).stream().anyMatch(v -> v > 1)) {
            log.debugv("Supplied password is in a pwned passwords breach");
            return new PolicyError("invalidPasswordBreached");
        }
        return null;
    }

    @SneakyThrows
    private String hash(String value) {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(value.getBytes(StandardCharsets.UTF_8));
        byte[] digest = md.digest();

        StringBuilder hexString = new StringBuilder();
        for (byte b : digest) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString().toUpperCase();
    }

    private int callKAnonymity(String hpw, KeycloakSession session) throws Exception {
        String prefix = hpw.substring(0, 5);
        log.debugv("Calling Pwned Passwords k-anonymity API for range: {0}", prefix);
        SimpleHttp.Response resp = SimpleHttp.doGet(String.format("https://api.pwnedpasswords.com/range/%s", prefix),
                                                    session)
                .connectionRequestTimeoutMillis(15000)
                .socketTimeOutMillis(30000)
                .connectTimeoutMillis(15000)
                .asResponse();

        if (resp.getStatus() != 200) {
            throw new Exception("Error calling k-anonymity API: " + resp.getStatus());
        }

        Scanner hashes = new Scanner(resp.asString());
        int thisCount = 0;

        while (hashes.hasNextLine()) {
            String row = hashes.nextLine();
            if (!Strings.isNullOrEmpty(row)) {
                String[] result = row.split(":");

                int count = 1;
                if (result.length == 2) {
                    count = Integer.parseInt(result[1].replaceAll(",", ""));
                }
                kCache.put((prefix + result[0]).toUpperCase(), count);
                if ((prefix + result[0]).equalsIgnoreCase(hpw)) {
                    thisCount = count;
                }
            }
        }
        kCache.put(hpw, thisCount);
        return thisCount;
    }

    @Override
    public Object parseConfig(String value) {
        return null;
    }

    @Override
    public void close() {

    }
}
