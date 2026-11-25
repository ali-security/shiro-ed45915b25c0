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
package org.apache.shiro.realm.text;

import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests that reloading a {@link PropertiesRealm} replaces its content: access can be revoked, not only granted.
 */
public class PropertiesRealmTest {
    private static final String INITIAL =
            "user.alice = pass1, admin\n" +
            "user.bob = pass2, admin\n" +
            "role.admin = *\n";

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    private File file;
    private PropertiesRealm realm;

    @Before
    public void setUp() throws IOException {
        file = tempDir.newFile("users.properties");
        write(INITIAL);
        realm = new PropertiesRealm();
        realm.setResourcePath("file:" + file.getAbsolutePath());
        // reloads are triggered explicitly, no background thread
        realm.setReloadIntervalSeconds(0);
        realm.init();
    }

    @After
    public void tearDown() {
        realm.destroy();
    }

    private void write(String content) throws IOException {
        Files.write(file.toPath(), content.getBytes(StandardCharsets.UTF_8));
    }

    private boolean authenticates(String user, String password) {
        return realm.getAuthenticationInfo(new UsernamePasswordToken(user, password)) != null;
    }

    private boolean permitted(String user, String permission) {
        PrincipalCollection principals = new SimplePrincipalCollection(user, realm.getName());
        return realm.isPermitted(principals, permission);
    }

    @Test
    public void initialStateIsLoaded() {
        assertTrue(authenticates("alice", "pass1"));
        assertTrue(authenticates("bob", "pass2"));
        assertTrue(permitted("bob", "anything:anything"));
    }

    @Test
    public void reloadRemovesDeletedUser() throws IOException {
        write("user.bob = pass2, admin\n" +
              "role.admin = *\n");
        realm.restart();

        assertFalse(authenticates("alice", "pass1"));
        assertFalse(permitted("alice", "anything:anything"));
        assertTrue(authenticates("bob", "pass2"));
    }

    @Test
    public void reloadRemovesNarrowedPermissions() throws IOException {
        write("user.alice = pass1, admin\n" +
              "user.bob = pass2, admin\n" +
              "role.admin = app:read\n");
        realm.restart();

        assertTrue(permitted("bob", "app:read"));
        assertFalse(permitted("bob", "anything:anything"));
    }

    @Test
    public void reloadRemovesDroppedRole() throws IOException {
        write("user.alice = pass1, admin, auditor\n" +
              "user.bob = pass2, auditor\n" +
              "role.admin = *\n" +
              "role.auditor = audit:read\n");
        realm.restart();
        assertTrue(permitted("bob", "audit:read"));
        assertFalse(permitted("bob", "anything:anything"));

        write("user.alice = pass1, auditor\n" +
              "user.bob = pass2\n" +
              "role.auditor = audit:read\n");
        realm.restart();
        assertFalse(permitted("alice", "anything:anything"));
        assertTrue(permitted("alice", "audit:read"));
        assertFalse(permitted("bob", "audit:read"));
    }

    @Test
    public void reloadAddsAndUpdatesUsers() throws IOException {
        write("user.alice = changed, admin\n" +
              "user.carol = pass3, admin\n" +
              "role.admin = *\n");
        realm.restart();

        assertTrue(authenticates("carol", "pass3"));
        assertTrue(authenticates("alice", "changed"));
        assertFalse(authenticates("bob", "pass2"));
    }

    @Test
    public void reloadClearsCachedInfo() throws IOException {
        realm.setCacheManager(new MemoryConstrainedCacheManager());
        realm.setAuthenticationCachingEnabled(true);
        realm.setAuthorizationCachingEnabled(true);
        assertTrue(authenticates("alice", "pass1"));
        assertTrue(permitted("alice", "anything:anything"));

        write("user.bob = pass2, admin\n" +
              "role.admin = *\n");
        realm.restart();

        assertFalse(authenticates("alice", "pass1"));
        assertFalse(permitted("alice", "anything:anything"));
    }

    @Test
    public void periodicReloadRemovesDeletedUserAndNarrowedPermissions() throws IOException {
        write("user.bob = pass2, admin\n" +
              "role.admin = app:read\n");
        // make sure the file is seen as modified, then run the periodic reload task directly
        assertTrue(file.setLastModified(System.currentTimeMillis() + 60000L));
        realm.run();

        assertFalse(authenticates("alice", "pass1"));
        assertFalse(permitted("alice", "app:read"));
        assertTrue(permitted("bob", "app:read"));
        assertFalse(permitted("bob", "anything:anything"));
    }

    @Test
    public void reloadRunsInitializationHooks() throws IOException {
        final AtomicInteger initCalls = new AtomicInteger();
        PropertiesRealm hooked = new PropertiesRealm() {
            @Override
            public void onInit() {
                super.onInit();
                initCalls.incrementAndGet();
            }
        };
        hooked.setResourcePath("file:" + file.getAbsolutePath());
        hooked.setReloadIntervalSeconds(0);
        hooked.init();
        assertEquals(1, initCalls.get());

        hooked.restart();

        assertEquals(2, initCalls.get());
        hooked.destroy();
    }
}
