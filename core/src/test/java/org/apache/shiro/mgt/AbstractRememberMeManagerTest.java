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

import org.apache.shiro.io.DefaultSerializer;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.junit.Test;

import java.time.Instant;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test cases for the {@link AbstractRememberMeManager} implementation.
 */
public class AbstractRememberMeManagerTest {

    /**
     * Tests the {@link AbstractRememberMeManager#getRememberedPrincipals(SubjectContext)} method
     * implementation when the internal
     * {@link AbstractRememberMeManager#getRememberedSerializedIdentity(SubjectContext)} method
     * returns null or empty bytes.
     */
    @Test
    public void testGetRememberedPrincipalsWithEmptySerializedBytes() {
        AbstractRememberMeManager rmm = new DummyRememberMeManager();
        //Since the dummy's getRememberedSerializedIdentity implementation returns an empty byte
        //array, we should be ok:
        PrincipalCollection principals = rmm.getRememberedPrincipals(new DefaultSubjectContext());
        assertNull(principals);

        //try with a null return value too:
        rmm = new DummyRememberMeManager() {
            @Override
            protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
                return null;
            }
        };
        principals = rmm.getRememberedPrincipals(new DefaultSubjectContext());
        assertNull(principals);
    }

    /**
     * The remembered identity must carry the time at which it was remembered (taken from
     * {@link AbstractRememberMeManager#now()}), and that time must be handed to
     * {@link AbstractRememberMeManager#checkExpiration(AbstractRememberMeManager.RememberedIdentity)} when the
     * identity is read back.
     */
    @Test
    public void testRememberedIdentityRecordsCreationTime() {
        ExpiringRememberMeManager rmm = new ExpiringRememberMeManager();
        Instant rememberedAt = Instant.parse("2021-01-01T00:00:00Z");
        rmm.now = rememberedAt;
        PrincipalCollection remembered = new SimplePrincipalCollection("user", "realm");

        byte[] bytes = rmm.convertPrincipalsToBytes(remembered);

        rmm.now = rememberedAt.plusSeconds(10);
        PrincipalCollection principals = rmm.convertBytesToPrincipals(bytes, new DefaultSubjectContext());

        assertNotNull(rmm.checkedIdentity);
        assertEquals(rememberedAt, rmm.checkedIdentity.creationTime());
        assertEquals(remembered, rmm.checkedIdentity.principals());
        assertEquals(remembered, principals);
    }

    /**
     * Replaying a remembered identity after its lifetime has elapsed must not log the user back in.
     */
    @Test
    public void testExpiredRememberedIdentityIsNotAccepted() {
        ExpiringRememberMeManager rmm = new ExpiringRememberMeManager();
        rmm.maxAgeSeconds = 60;
        Instant rememberedAt = Instant.parse("2021-01-01T00:00:00Z");
        rmm.now = rememberedAt;
        PrincipalCollection remembered = new SimplePrincipalCollection("user", "realm");
        rmm.rememberIdentity(null, remembered);
        assertNotNull(rmm.rememberedBytes);

        // still within the configured lifetime
        rmm.now = rememberedAt.plusSeconds(60);
        assertEquals(remembered, rmm.getRememberedPrincipals(new DefaultSubjectContext()));

        // the very same remembered bytes replayed after the lifetime has elapsed
        rmm.now = rememberedAt.plusSeconds(61);
        assertNull(rmm.getRememberedPrincipals(new DefaultSubjectContext()));
        assertEquals(rememberedAt, rmm.checkedIdentity.creationTime());
    }

    /**
     * A remembered identity that does not record when it was created (such as one that only contains a serialized
     * {@code PrincipalCollection}) cannot be checked for expiration and must not be accepted.
     */
    @Test
    public void testRememberedIdentityWithoutCreationTimeIsNotAccepted() {
        ExpiringRememberMeManager rmm = new ExpiringRememberMeManager();
        PrincipalCollection remembered = new SimplePrincipalCollection("user", "realm");
        byte[] serialized = new DefaultSerializer<PrincipalCollection>().serialize(remembered);
        rmm.rememberedBytes = rmm.encrypt(serialized);

        try {
            PrincipalCollection principals = rmm.getRememberedPrincipals(new DefaultSubjectContext());
            fail("A remembered identity without a creation time must not be accepted, but got " + principals);
        } catch (RuntimeException expected) {
            //expected - the remembered bytes do not contain a RememberedIdentity
        }
        assertTrue(rmm.forgotten);
        assertNull(rmm.checkedIdentity);
    }

    /**
     * Without an expiration policy the default {@code checkExpiration} implementation returns the remembered
     * principals.
     */
    @Test
    public void testDefaultCheckExpirationReturnsPrincipals() {
        ExpiringRememberMeManager rmm = new ExpiringRememberMeManager();
        PrincipalCollection remembered = new SimplePrincipalCollection("user", "realm");
        rmm.rememberIdentity(null, remembered);

        assertEquals(remembered, rmm.getRememberedPrincipals(new DefaultSubjectContext()));
        assertFalse(rmm.forgotten);
    }

    /**
     * Remember me manager that keeps the remembered bytes in memory, uses a controllable clock and
     * optionally enforces a maximum age (in seconds) on remembered identities.
     */
    static class ExpiringRememberMeManager extends AbstractRememberMeManager {
        Instant now = Instant.now();
        long maxAgeSeconds = -1;
        byte[] rememberedBytes;
        RememberedIdentity checkedIdentity;
        boolean forgotten;

        @Override
        protected Instant now() {
            return now;
        }

        @Override
        protected PrincipalCollection checkExpiration(RememberedIdentity remembered) {
            checkedIdentity = remembered;
            if (maxAgeSeconds >= 0 && now().isAfter(remembered.creationTime().plusSeconds(maxAgeSeconds))) {
                return null;
            }
            return super.checkExpiration(remembered);
        }

        @Override
        protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
            rememberedBytes = serialized;
        }

        @Override
        protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
            return rememberedBytes;
        }

        @Override
        protected void forgetIdentity(Subject subject) {
            forgotten = true;
        }

        @Override
        public void forgetIdentity(SubjectContext subjectContext) {
            forgotten = true;
        }
    }

    private static class DummyRememberMeManager extends AbstractRememberMeManager {
        public void forgetIdentity(SubjectContext subjectContext) {
            //do nothing
        }

        @Override
        protected void forgetIdentity(Subject subject) {
        }

        @Override
        protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
        }

        @Override
        protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
            return new byte[0];
        }
    }
}
