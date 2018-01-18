package de.svg.keycloak.providers.credential.hash;

import org.apache.commons.codec.digest.Md5Crypt;
import org.keycloak.Config;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.UserCredentialModel;

public class CustomPasswordHashProvider implements PasswordHashProviderFactory, PasswordHashProvider {

    private static final String ID = "mysvg24";

    @Override
    public boolean policyCheck(PasswordPolicy policy, CredentialModel credential) {
        return credential.getHashIterations() == policy.getHashIterations() && ID.equals(credential.getAlgorithm());
    }

    @Override
    public void encode(String rawPassword, int iterations, CredentialModel credential) {
        String encodedPassword = Md5Crypt.md5Crypt(rawPassword.getBytes());

        credential.setAlgorithm(ID);
        credential.setType(UserCredentialModel.PASSWORD);
        credential.setSalt(encodedPassword.getBytes());
        credential.setHashIterations(iterations);
        credential.setValue(encodedPassword);
    }

    @Override
    public boolean verify(String rawPassword, CredentialModel credential) {
        String encodedPassword = Md5Crypt.md5Crypt(rawPassword.getBytes(), credential.getValue());
        return encodedPassword.equals(credential.getValue());
    }

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}
