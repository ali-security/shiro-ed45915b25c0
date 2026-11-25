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
package org.apache.shiro.realm.ldap;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.junit.Before;
import org.junit.Test;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * Verifies that, with authentication caching enabled, a {@link DefaultLdapRealm} still verifies the submitted
 * credentials against a cached {@link AuthenticationInfo}: once a user has logged in successfully, a later login
 * attempt for the same user with a wrong password must be rejected even though the LDAP bind is skipped
 * (CVE-2026-129349).
 */
public class DefaultLdapRealmAuthCachingTest {

    private static final String TEMPLATE = "uid={0},ou=users,dc=mycompany,dc=com";
    private static final String USERNAME = "jsmith";
    private static final String USER_DN = "uid=jsmith,ou=users,dc=mycompany,dc=com";
    private static final String PASSWORD = "secret";

    private DefaultLdapRealm realm;
    private LdapContextFactory factory;
    private LdapContext ctx;

    @Before
    public void setUp() throws NamingException {
        realm = new DefaultLdapRealm();
        realm.setUserDnTemplate(TEMPLATE);
        realm.setCacheManager(new MemoryConstrainedCacheManager());
        realm.setAuthenticationCachingEnabled(true);

        factory = createStrictMock(LdapContextFactory.class);
        ctx = createStrictMock(LdapContext.class);
        realm.setContextFactory(factory);

        // the directory accepts exactly one bind, with the correct password; every later attempt must be
        // served from the authentication cache
        expect(factory.getLdapContext(eq(USER_DN), aryEq(PASSWORD.toCharArray()))).andReturn(ctx).once();
        ctx.close();
        expectLastCall().once();
        replay(factory, ctx);
    }

    @Test
    public void testCachedAuthenticationRejectsWrongPassword() {
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD));
        assertNotNull(info);
        assertEquals(USERNAME, info.getPrincipals().getPrimaryPrincipal());

        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, "wrong-password"));
            fail("A cached LDAP authentication must not accept a wrong password");
        } catch (IncorrectCredentialsException expected) {
            // expected: the cached credentials do not match the submitted ones
        }

        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, ""));
            fail("A cached LDAP authentication must not accept an empty password");
        } catch (IncorrectCredentialsException expected) {
            // expected
        }

        verify(factory, ctx);
    }

    @Test
    public void testCachedAuthenticationAcceptsCorrectPassword() {
        AuthenticationInfo first = realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD));
        assertNotNull(first);

        // served from the cache (no second bind), and the cached credentials still match the correct password
        AuthenticationInfo second = realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD));
        assertNotNull(second);
        assertEquals(USERNAME, second.getPrincipals().getPrimaryPrincipal());

        verify(factory, ctx);
    }

    @Test
    public void testSecurityManagerRejectsWrongPasswordAfterCachedLogin() {
        DefaultSecurityManager securityManager = new DefaultSecurityManager(realm);
        securityManager.setCacheManager(new MemoryConstrainedCacheManager());

        AuthenticationInfo info = securityManager.authenticate(new UsernamePasswordToken(USERNAME, PASSWORD));
        assertEquals(USERNAME, info.getPrincipals().getPrimaryPrincipal());

        try {
            securityManager.authenticate(new UsernamePasswordToken(USERNAME, "wrong-password"));
            fail("A cached LDAP authentication must not accept a wrong password");
        } catch (AuthenticationException expected) {
            // expected
        }

        verify(factory, ctx);
    }
}
