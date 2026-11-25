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

import org.apache.shiro.authc.UsernamePasswordToken;
import org.junit.Before;
import org.junit.Test;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * Verifies that {@link DefaultLdapRealm} escapes RFC 2253 special characters in the submitted principal before
 * substituting it into the configured {@code userDnTemplate}, so a crafted username cannot alter the User DN used
 * for the LDAP bind (LDAP DN injection, CVE-2026-49268).
 */
public class DefaultLdapRealmUserDnEscapingTest {

    private static final String TEMPLATE = "uid={0},ou=users,dc=mycompany,dc=com";

    // number of RDNs in TEMPLATE
    private static final int TEMPLATE_RDN_COUNT = 4;

    private DefaultLdapRealm realm;

    @Before
    public void setUp() {
        realm = new DefaultLdapRealm();
        realm.setUserDnTemplate(TEMPLATE);
    }

    /**
     * Asserts that the DN built for the given principal has exactly the template's structure, with the principal
     * (unaltered) as the single-valued value of the leading {@code uid} RDN.
     */
    private void assertPrincipalConfinedToUidRdn(String principal) throws NamingException {
        String userDn = realm.getUserDn(principal);
        LdapName name = new LdapName(userDn);
        assertEquals("injected RDNs in User DN [" + userDn + "]", TEMPLATE_RDN_COUNT, name.size());
        Rdn leaf = name.getRdn(name.size() - 1);
        assertEquals("injected multi-valued RDN in User DN [" + userDn + "]", 1, leaf.size());
        assertEquals("uid", leaf.getType());
        assertEquals(principal, leaf.getValue());
        assertTrue(userDn.endsWith(",ou=users,dc=mycompany,dc=com"));
    }

    @Test
    public void testGetUserDnEscapesInjectedRdns() throws NamingException {
        String userDn = realm.getUserDn("jsmith,ou=admins");
        assertEquals("uid=jsmith\\,ou\\=admins,ou=users,dc=mycompany,dc=com", userDn);
        assertPrincipalConfinedToUidRdn("jsmith,ou=admins");
        assertPrincipalConfinedToUidRdn("admin,ou=users,dc=othercompany,dc=com");
    }

    @Test
    public void testGetUserDnEscapesInjectedMultiValuedRdn() throws NamingException {
        String userDn = realm.getUserDn("jsmith+uid=admin");
        assertEquals("uid=jsmith\\+uid\\=admin,ou=users,dc=mycompany,dc=com", userDn);
        assertPrincipalConfinedToUidRdn("jsmith+uid=admin");
    }

    @Test
    public void testGetUserDnEscapesAllSpecialCharacters() throws NamingException {
        assertPrincipalConfinedToUidRdn("a\"b<c>d;e\\f=g+h,i");
        assertPrincipalConfinedToUidRdn("#jsmith");
        assertPrincipalConfinedToUidRdn(" jsmith ");
    }

    @Test
    public void testGetUserDnLeavesPlainPrincipalUnchanged() {
        assertEquals("uid=jsmith,ou=users,dc=mycompany,dc=com", realm.getUserDn("jsmith"));
        assertEquals("uid=j.smith@mycompany.com,ou=users,dc=mycompany,dc=com", realm.getUserDn("j.smith@mycompany.com"));
        assertEquals(TEMPLATE, realm.getUserDnTemplate());
    }

    @Test
    public void testAuthenticationBindsWithEscapedUserDn() throws NamingException {
        LdapContextFactory factory = createMock(LdapContextFactory.class);
        realm.setContextFactory(factory);

        // the bind must target the escaped DN, never "uid=admin,ou=admins,ou=users,dc=mycompany,dc=com"
        Object expectedPrincipal = "uid=admin\\,ou\\=admins,ou=users,dc=mycompany,dc=com";

        expect(factory.getLdapContext(eq(expectedPrincipal), isA(Object.class))).andReturn(createNiceMock(LdapContext.class));
        replay(factory);

        realm.getAuthenticationInfo(new UsernamePasswordToken("admin,ou=admins", "secret"));
        verify(factory);
    }
}
