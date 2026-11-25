/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.junit.Test;

import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Verifies that authentication attempts for non-existent accounts perform the same credentials matching work as
 * attempts for existing accounts, so that account existence cannot be inferred from response timing.
 */
public class AuthenticatingRealmJavaTest {

    /**
     * should create a SHA-256 (default) password hash when user does not exist
     */
    @Test
    public void authenticatingRealmShouldCreateSha256HashWhenUserDoesNotExist() {
        // given
        CountingPasswordMatcher passwordMatcher = new CountingPasswordMatcher();
        AuthenticationToken token = new UsernamePasswordToken("username", "password".toCharArray());
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(passwordMatcher);

        // when
        AuthenticationInfo info = realm.getAuthenticationInfo(token);

        // then
        assertNull(info);
        assertEquals(1, passwordMatcher.simulatedCredentialsCount);
        // the submitted credentials were really checked against the simulated (hashed) credentials
        assertEquals(1, passwordMatcher.credentialsMatchCount);

        Object simulatedCredentials = realm.authInfo.getCredentials();
        assertTrue(simulatedCredentials instanceof String);
        assertTrue(simulatedCredentials.toString().startsWith(
                "$shiro1$SHA-256$" + DefaultPasswordService.DEFAULT_HASH_ITERATIONS + "$"));
    }

    /**
     * should create a SHA-512 password hash when user does not exist
     */
    @Test
    public void authenticatingRealmShouldCreateSha512HashWhenUserDoesNotExist() {
        // given
        DefaultHashService sha512HashService = new DefaultHashService();
        sha512HashService.setHashAlgorithmName("SHA-512");
        sha512HashService.setHashIterations(1024);
        sha512HashService.setGeneratePublicSalt(true);
        DefaultPasswordService defaultPasswordService = new DefaultPasswordService();
        defaultPasswordService.setHashService(sha512HashService);
        CountingPasswordMatcher passwordMatcher = new CountingPasswordMatcher();
        passwordMatcher.setPasswordService(defaultPasswordService);

        AuthenticationToken token = new UsernamePasswordToken("username", "password".toCharArray());
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(passwordMatcher);

        // when
        AuthenticationInfo info = realm.getAuthenticationInfo(token);

        // then
        assertNull(info);
        assertEquals(1, passwordMatcher.simulatedCredentialsCount);
        assertEquals(1, passwordMatcher.credentialsMatchCount);

        Object simulatedCredentials = realm.authInfo.getCredentials();
        assertTrue(simulatedCredentials instanceof String);
        assertTrue(simulatedCredentials.toString().startsWith("$shiro1$SHA-512$1024$"));
    }

    /**
     * A non-existent account must cost the same number of (iterated) hash computations as an existing account
     * with a wrong password; before the fix, a missing account returned immediately without hashing anything.
     */
    @Test
    public void unknownUserShouldBeHashedLikeExistingUser() {
        // given
        CountingHashedCredentialsMatcher matcher = new CountingHashedCredentialsMatcher(Sha256Hash.ALGORITHM_NAME);
        matcher.setHashIterations(1024);
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.setCredentialsMatcher(matcher);
        realm.addAccount("existing", new Sha256Hash("secret", null, 1024).toHex());

        // when - existing account, wrong password
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken("existing", "wrong"));
            fail("IncorrectCredentialsException should have been thrown.");
        } catch (IncorrectCredentialsException expected) {
        }
        int existingUserHashCount = matcher.hashCount;

        // when - non-existent account
        matcher.hashCount = 0;
        matcher.lastHashIterations = 0;
        AuthenticationInfo unknownUserInfo =
                realm.getAuthenticationInfo(new UsernamePasswordToken("unknown", "wrong"));

        // then
        assertNull(unknownUserInfo);
        assertEquals(1, existingUserHashCount);
        assertEquals(existingUserHashCount, matcher.hashCount);
        assertEquals(1024, matcher.lastHashIterations);

        // and the existing account can still log in
        assertNotNull(realm.getAuthenticationInfo(new UsernamePasswordToken("existing", "secret")));
    }

    /**
     * A non-existent account must cost the same password service work as an existing account
     * with a wrong password when using a {@link PasswordMatcher}.
     */
    @Test
    public void unknownUserShouldBeVerifiedByPasswordServiceLikeExistingUser() {
        // given
        DefaultHashService hashService = new DefaultHashService();
        hashService.setHashAlgorithmName(Sha256Hash.ALGORITHM_NAME);
        hashService.setHashIterations(1024);
        hashService.setGeneratePublicSalt(true);
        CountingPasswordService passwordService = new CountingPasswordService();
        passwordService.setHashService(hashService);
        PasswordMatcher matcher = new PasswordMatcher();
        matcher.setPasswordService(passwordService);
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.setCredentialsMatcher(matcher);
        realm.addAccount("existing", passwordService.encryptPassword("secret"));

        // when - existing account, wrong password
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken("existing", "wrong"));
            fail("IncorrectCredentialsException should have been thrown.");
        } catch (IncorrectCredentialsException expected) {
        }
        int existingUserMatchCount = passwordService.passwordsMatchCount;

        // when - non-existent account
        passwordService.passwordsMatchCount = 0;
        AuthenticationInfo unknownUserInfo =
                realm.getAuthenticationInfo(new UsernamePasswordToken("unknown", "wrong"));

        // then
        assertNull(unknownUserInfo);
        assertEquals(1, existingUserMatchCount);
        assertEquals(existingUserMatchCount, passwordService.passwordsMatchCount);

        // and the existing account can still log in
        assertNotNull(realm.getAuthenticationInfo(new UsernamePasswordToken("existing", "secret")));
    }

    @Test
    public void simulatedCredentialsShouldOnlyBeCreatedOnce() {
        // given
        CountingPasswordMatcher passwordMatcher = new CountingPasswordMatcher();
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(passwordMatcher);

        // when
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password")));
        AuthenticationInfo firstSimulated = realm.authInfo;
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("other", "password")));

        // then
        assertEquals(1, passwordMatcher.simulatedCredentialsCount);
        assertEquals(2, passwordMatcher.credentialsMatchCount);
        assertNotNull(firstSimulated);
        assertSame(firstSimulated, realm.authInfo);
    }

    @Test
    public void simpleCredentialsMatcherShouldSimulateRandomCredentials() {
        // given
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        assertTrue(realm.getCredentialsMatcher() instanceof SimpleCredentialsMatcher);

        // when
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password"));

        // then
        assertNull(info);
        assertNotNull(realm.authInfo);
        assertNotNull(realm.authInfo.getCredentials());
    }

    @Test
    public void allowAllCredentialsMatcherShouldNotAuthenticateUnknownUser() {
        // given
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(new AllowAllCredentialsMatcher());

        // when
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password"));

        // then
        assertNull(info);
        assertNotNull(realm.authInfo);
    }

    @Test
    public void matcherWithoutSimulatedCredentialsShouldStillReturnNull() {
        // given
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(new LegacyCredentialsMatcher());

        // when
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password"));

        // then
        assertNull(info);
        assertNull(realm.authInfo);
    }

    @Test
    public void nullCredentialsMatcherShouldStillReturnNullForUnknownUser() {
        // given
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(null);

        // when
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password"));

        // then
        assertNull(info);
        assertNull(realm.authInfo);
    }

    /**
     * For the test, it is important that this class returns {@code null} for
     * {@link AuthenticatingRealm#doGetAuthenticationInfo(AuthenticationToken)},
     * so that simulatedAuthenticationInfo is being created.
     */
    static class NullAuthenticatingRealm extends AuthenticatingRealm {

        /**
         * captured created authenticationInfo
         */
        private AuthenticationInfo authInfo;

        @Override
        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {
            return null;
        }

        /**
         * Captures the created authenticationInfo for tests.
         * @return see super method.
         */
        @Override
        AuthenticationInfo ensureSimulatedAuthenticationInfo() {
            final AuthenticationInfo authInfo1 = super.ensureSimulatedAuthenticationInfo();
            this.authInfo = authInfo1;
            return authInfo1;
        }
    }

    /**
     * {@link PasswordMatcher} counting the calls relevant for simulated authentication.
     */
    static class CountingPasswordMatcher extends PasswordMatcher {

        private int simulatedCredentialsCount;
        private int credentialsMatchCount;

        @Override
        public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
            credentialsMatchCount++;
            return super.doCredentialsMatch(token, info);
        }

        @Override
        public Optional<AuthenticationInfo> createSimulatedCredentials() {
            simulatedCredentialsCount++;
            return super.createSimulatedCredentials();
        }
    }

    /**
     * {@link HashedCredentialsMatcher} counting the hash computations of submitted credentials.
     */
    static class CountingHashedCredentialsMatcher extends HashedCredentialsMatcher {

        private int hashCount;
        private int lastHashIterations;

        CountingHashedCredentialsMatcher(String hashAlgorithmName) {
            super(hashAlgorithmName);
        }

        @Override
        protected Hash hashProvidedCredentials(Object credentials, Object salt, int hashIterations) {
            hashCount++;
            lastHashIterations = hashIterations;
            return super.hashProvidedCredentials(credentials, salt, hashIterations);
        }
    }

    /**
     * {@link DefaultPasswordService} counting the password verifications.
     */
    static class CountingPasswordService extends DefaultPasswordService {

        private int passwordsMatchCount;

        @Override
        public boolean passwordsMatch(Object submittedPlaintext, String saved) {
            passwordsMatchCount++;
            return super.passwordsMatch(submittedPlaintext, saved);
        }
    }

    /**
     * {@link CredentialsMatcher} which does not supply simulated credentials (pre-existing implementations).
     */
    static class LegacyCredentialsMatcher implements CredentialsMatcher {

        @Override
        public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
            return true;
        }
    }
}
