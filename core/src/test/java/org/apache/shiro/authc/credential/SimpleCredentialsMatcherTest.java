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
package org.apache.shiro.authc.credential;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.util.ByteSource;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Unit tests for the {@link SimpleCredentialsMatcher} implementation: an empty or missing stored credential must
 * never be treated as a match for an empty submitted password.
 */
public class SimpleCredentialsMatcherTest {

    private static final String USERNAME = "user";

    private static AuthenticationInfo info(Object credentials) {
        return new SimpleAuthenticationInfo(USERNAME, credentials, "realm");
    }

    @Test
    public void testEmptyStoredStringDoesNotMatchEmptyPassword() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, ""), info("")));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, new char[0]), info("")));
    }

    @Test
    public void testEmptyStoredCharArrayDoesNotMatchEmptyPassword() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, ""), info(new char[0])));
    }

    @Test
    public void testEmptyStoredByteArrayDoesNotMatchEmptyPassword() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, ""), info(new byte[0])));
        assertFalse(matcher.equals(new byte[0], new byte[0]));
    }

    @Test
    public void testEmptyStoredByteSourceDoesNotMatchEmptyPassword() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, ""),
                info(ByteSource.Util.bytes(new byte[0]))));
    }

    @Test
    public void testNullStoredCredentialsNeverMatch() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, (char[]) null), info(null)));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, ""), info(null)));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, "secret"), info(null)));
    }

    @Test
    public void testNonEmptyCredentialsStillMatch() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        assertTrue(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, "secret"), info("secret")));
        assertTrue(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, "secret"),
                info("secret".toCharArray())));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, "wrong"), info("secret")));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken(USERNAME, ""), info("secret")));
    }

    @Test
    public void testRealmRejectsEmptyPasswordForAccountWithEmptyStoredPassword() {
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.addAccount(USERNAME, "");
        realm.addAccount("other", "secret");
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, ""));
            fail("An empty password must not authenticate an account whose stored password is empty");
        } catch (IncorrectCredentialsException expected) {
            // expected
        }

        AuthenticationInfo other = realm.getAuthenticationInfo(new UsernamePasswordToken("other", "secret"));
        assertNotNull(other);
        assertEquals("other", other.getPrincipals().getPrimaryPrincipal());
    }

    @Test
    public void testRealmWithPasswordMatcherRejectsEmptyPasswordForEmptyStoredPassword() {
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.setCredentialsMatcher(new PasswordMatcher());
        realm.addAccount(USERNAME, "");
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, ""));
            fail("An empty password must not authenticate an account whose stored password is empty");
        } catch (IncorrectCredentialsException expected) {
            // expected
        }
    }
}
