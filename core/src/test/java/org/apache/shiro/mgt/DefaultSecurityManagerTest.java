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
package org.apache.shiro.mgt;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.AbstractValidatingSessionManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.subject.support.DelegatingSubject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;

import static org.junit.Assert.*;


/**
 * @since 0.2
 */
public class DefaultSecurityManagerTest extends AbstractSecurityManagerTest {

    DefaultSecurityManager sm = null;

    @Before
    public void setup() {
        sm = new DefaultSecurityManager();
        Ini ini = new Ini();
        Ini.Section section = ini.addSection(IniRealm.USERS_SECTION_NAME);
        section.put("guest", "guest, guest");
        section.put("lonestarr", "vespa, goodguy");
        sm.setRealm(new IniRealm(ini));
        SecurityUtils.setSecurityManager(sm);
    }

    @After
    public void tearDown() {
        SecurityUtils.setSecurityManager(null);
        sm.destroy();
        super.tearDown();
    }

    @Test
    public void testDefaultConfig() {
        Subject subject = SecurityUtils.getSubject();

        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login(token);
        assertTrue(subject.isAuthenticated());
        assertTrue("guest".equals(subject.getPrincipal()));
        assertTrue(subject.hasRole("guest"));

        Session session = subject.getSession();
        session.setAttribute("key", "value");
        assertEquals(session.getAttribute("key"), "value");

        subject.logout();

        assertNull(subject.getSession(false));
        assertNull(subject.getPrincipal());
        assertNull(subject.getPrincipals());
    }

    /**
     * Test that validates functionality for issue
     * <a href="https://issues.apache.org/jira/browse/JSEC-46">JSEC-46</a>
     */
    @Test
    public void testAutoCreateSessionAfterInvalidation() {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        Serializable origSessionId = session.getId();

        String key = "foo";
        String value1 = "bar";
        session.setAttribute(key, value1);
        assertEquals(value1, session.getAttribute(key));

        //now test auto creation:
        session.setTimeout(50);
        try {
            Thread.sleep(150);
        } catch (InterruptedException e) {
            //ignored
        }
        try {
            session.setTimeout(AbstractValidatingSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT);
            fail("Session should have expired.");
        } catch (ExpiredSessionException expected) {
        }
    }

    /**
     * Test that validates functionality for issue
     * <a href="https://issues.apache.org/jira/browse/JSEC-22">JSEC-22</a>
     */
    @Test
    public void testSubjectReuseAfterLogout() {

        Subject subject = SecurityUtils.getSubject();

        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login(token);
        assertTrue(subject.isAuthenticated());
        assertTrue("guest".equals(subject.getPrincipal()));
        assertTrue(subject.hasRole("guest"));

        Session session = subject.getSession();
        Serializable firstSessionId = session.getId();

        session.setAttribute("key", "value");
        assertEquals(session.getAttribute("key"), "value");

        subject.logout();

        assertNull(subject.getSession(false));
        assertNull(subject.getPrincipal());
        assertNull(subject.getPrincipals());

        subject.login(new UsernamePasswordToken("lonestarr", "vespa"));
        assertTrue(subject.isAuthenticated());
        assertTrue("lonestarr".equals(subject.getPrincipal()));
        assertTrue(subject.hasRole("goodguy"));

        assertNotNull(subject.getSession());
        assertFalse(firstSessionId.equals(subject.getSession().getId()));

        subject.logout();

        assertNull(subject.getSession(false));
        assertNull(subject.getPrincipal());
        assertNull(subject.getPrincipals());

    }

    /**
     * Test ensures that a {@link Subject#login(AuthenticationToken)} first uses
     * the {@link SecurityManager} passed to its {@link Subject.Builder}
     * (if one was) instead of the one found in either the {@link ThreadContext}
     * or statically in {@link SecurityUtils}, either of which may not exist.
     * <a href="https://issues.apache.org/jira/browse/SHIRO-457">SHIRO-457</a>
     */
    @Test
    public void testNewSubjectWithoutThreadSecurityManager() {
        // Ensure no fallback sm exists in thread context or statically
        SecurityUtils.setSecurityManager(null);
        try {
            SecurityUtils.getSecurityManager();
        } catch (UnavailableSecurityManagerException e) {
            assertTrue(e.getMessage().startsWith("No SecurityManager accessible"));
        }

        // Specify sm to use and build subject with
        DelegatingSubject subject =
            (DelegatingSubject)(new Subject.Builder(sm)).buildSubject();

        // Login and verify specified sm is used and no error thrown
        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login(token);
        assertEquals(sm, subject.getSecurityManager());
    }

    /**
     * Session fixation via RememberMe (CVE-2026-74762): when a Subject is restored from a RememberMe identity, the
     * existing (possibly attacker-supplied) session must be invalidated and a new session with a new ID created.
     */
    @Test
    public void testRememberMeRestoreRotatesFixatedSession() {
        // attacker obtains an anonymous session and plants its ID on the victim
        Subject attacker = new Subject.Builder(sm).buildSubject();
        Session fixatedSession = attacker.getSession();
        Serializable fixatedSessionId = fixatedSession.getId();
        assertNotNull(fixatedSessionId);
        fixatedSession.setAttribute("key", "value");

        // victim's request carries the fixated session ID and a valid RememberMe identity
        sm.setRememberMeManager(new FixedRememberMeManager(new SimplePrincipalCollection("guest", "iniRealm")));
        Subject victim = new Subject.Builder(sm).sessionId(fixatedSessionId).buildSubject();

        assertTrue(victim.isRemembered());
        assertEquals("guest", victim.getPrincipal());
        Session victimSession = victim.getSession(false);
        assertNotNull(victimSession);
        assertNotEquals("session ID must change when the subject is restored from RememberMe",
                fixatedSessionId, victimSession.getId());
        assertEquals("session attributes must survive session rotation", "value", victimSession.getAttribute("key"));

        // follow-up requests on the rotated session resolve the identity from the session and keep its ID
        Subject resumed = new Subject.Builder(sm).sessionId(victimSession.getId()).buildSubject();
        assertEquals("guest", resumed.getPrincipal());
        assertEquals(victimSession.getId(), resumed.getSession(false).getId());

        // attacker replays the fixated session ID: it must not resolve to the victim's remembered identity
        sm.setRememberMeManager(null);
        Subject hijacked = new Subject.Builder(sm).sessionId(fixatedSessionId).buildSubject();
        assertNull(hijacked.getPrincipal());
        assertNull(hijacked.getSession(false));
    }

    @Test
    public void testExistingSessionNotRotatedWithoutRememberedIdentity() {
        Subject subject = new Subject.Builder(sm).buildSubject();
        Serializable sessionId = subject.getSession().getId();

        Subject resumed = new Subject.Builder(sm).sessionId(sessionId).buildSubject();
        assertFalse(resumed.isRemembered());
        assertEquals(sessionId, resumed.getSession(false).getId());
    }

    @Test
    public void testRememberedPrincipalsFlagOnSubjectContext() {
        DefaultSubjectContext context = new DefaultSubjectContext();
        assertFalse(context.isRememberedPrincipals());

        DefaultSecurityManager rememberingSm = new DefaultSecurityManager();
        rememberingSm.setRememberMeManager(
                new FixedRememberMeManager(new SimplePrincipalCollection("guest", "iniRealm")));
        SubjectContext resolved = rememberingSm.resolvePrincipals(context);
        assertTrue(resolved.isRememberedPrincipals());
        assertTrue(new DefaultSubjectContext(resolved).isRememberedPrincipals());

        DefaultSubjectContext authenticated = new DefaultSubjectContext();
        authenticated.setPrincipals(new SimplePrincipalCollection("guest", "iniRealm"));
        assertFalse(rememberingSm.resolvePrincipals(authenticated).isRememberedPrincipals());
        rememberingSm.destroy();
    }

    /**
     * RememberMeManager that always returns the same remembered identity.
     */
    static class FixedRememberMeManager implements RememberMeManager {

        private final PrincipalCollection principals;

        FixedRememberMeManager(PrincipalCollection principals) {
            this.principals = principals;
        }

        public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
            return principals;
        }

        public void forgetIdentity(SubjectContext subjectContext) {
        }

        public void onSuccessfulLogin(Subject subject, AuthenticationToken token, AuthenticationInfo info) {
        }

        public void onFailedLogin(Subject subject, AuthenticationToken token, AuthenticationException ae) {
        }

        public void onLogout(Subject subject) {
        }
    }
}
