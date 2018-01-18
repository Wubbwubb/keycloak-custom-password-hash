package org.keycloak.examples.providers.credential.hash;

import org.junit.Assert;
import org.junit.Test;

import org.keycloak.credential.CredentialModel;

public class CustomPasswordHashProviderTest  {
    @Test
    public void verify() {
        String plainPrivateCredential = "hallo";
//        String hashPrivateCredential = "$1$H70Mwv/s$0aYhZyCPcP8w7wYLys6WQ0";

        CustomPasswordHashProvider hashProvider = new CustomPasswordHashProvider();

        CredentialModel credentialModel = new CredentialModel();
        hashProvider.encode(plainPrivateCredential, 5, credentialModel);

        // the following assertion could be used to test a known password hash from typo3
//        Assert.assertEquals(hashPrivateCredential, credentialModel.getValue());

        Assert.assertTrue(hashProvider.verify(plainPrivateCredential, credentialModel));
    }
}
