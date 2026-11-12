/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.realm;

import java.net.InetAddress;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.InitialDirContext;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.juli.logging.LogFactory;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

/**
 * Tests that, when the JNDI realm validates a user's credentials by binding as
 * that user (i.e. <code>userPassword</code> is not set), a simple bind is
 * always used irrespective of the authentication mechanism configured for the
 * realm's own connection. Mechanisms such as <code>none</code> or
 * <code>EXTERNAL</code> ignore the provided password and must not be used to
 * validate user credentials.
 */
public class TestJNDIRealmBindAsUser {

    private static final String USER_PATTERN = "cn={0},ou=people,dc=example,dc=com";
    private static final String USER_SEARCH = "cn={0}";
    private static final String USER_BASE = "ou=people,dc=example,dc=com";

    private static final String USER = "test";
    private static final String USER_DN = "cn=test,ou=people,dc=example,dc=com";
    private static final String PASSWORD = "test";
    private static final String WRONG_PASSWORD = "not-the-password";

    private static InMemoryDirectoryServer ldapServer;


    /*
     * Integration tests against an in-memory LDAP server.
     */

    @Test
    public void testAuthenticationNoneUserPatternWrongPassword() throws Exception {
        JNDIRealm realm = createRealm("none", true);
        Assert.assertNull(realm.authenticate(USER, WRONG_PASSWORD));
    }


    @Test
    public void testAuthenticationNoneUserPatternCorrectPassword() throws Exception {
        JNDIRealm realm = createRealm("none", true);
        Principal p = realm.authenticate(USER, PASSWORD);
        Assert.assertNotNull(p);
        Assert.assertEquals(USER, p.getName());
    }


    @Test
    public void testAuthenticationNoneUserSearchWrongPassword() throws Exception {
        JNDIRealm realm = createRealm("none", false);
        Assert.assertNull(realm.authenticate(USER, WRONG_PASSWORD));
    }


    @Test
    public void testAuthenticationNoneUserSearchCorrectPassword() throws Exception {
        JNDIRealm realm = createRealm("none", false);
        Principal p = realm.authenticate(USER, PASSWORD);
        Assert.assertNotNull(p);
        Assert.assertEquals(USER, p.getName());
    }


    @Test
    public void testAuthenticationNoneRepeated() throws Exception {
        // Ensure the configured mechanism is restored after each bind attempt
        // and that subsequent attempts are still validated correctly
        JNDIRealm realm = createRealm("none", true);
        Assert.assertNull(realm.authenticate(USER, WRONG_PASSWORD));
        Assert.assertNotNull(realm.authenticate(USER, PASSWORD));
        Assert.assertNull(realm.authenticate(USER, WRONG_PASSWORD));
        Assert.assertNotNull(realm.authenticate(USER, PASSWORD));
    }


    @Test
    public void testAuthenticationSimpleWrongPassword() throws Exception {
        JNDIRealm realm = createRealm("simple", true);
        Assert.assertNull(realm.authenticate(USER, WRONG_PASSWORD));
    }


    @Test
    public void testAuthenticationSimpleCorrectPassword() throws Exception {
        JNDIRealm realm = createRealm("simple", true);
        Principal p = realm.authenticate(USER, PASSWORD);
        Assert.assertNotNull(p);
        Assert.assertEquals(USER, p.getName());
    }


    @Test
    public void testAuthenticationDefaultWrongPassword() throws Exception {
        JNDIRealm realm = createRealm(null, true);
        Assert.assertNull(realm.authenticate(USER, WRONG_PASSWORD));
    }


    @Test
    public void testAuthenticationDefaultCorrectPassword() throws Exception {
        JNDIRealm realm = createRealm(null, true);
        Principal p = realm.authenticate(USER, PASSWORD);
        Assert.assertNotNull(p);
        Assert.assertEquals(USER, p.getName());
    }


    /*
     * Tests of bindAsUser() for mechanisms that can't be negotiated with the
     * in-memory LDAP server (e.g. EXTERNAL requires a TLS client certificate).
     * The tester context behaves like a directory server: a simple bind
     * validates the supplied password whereas any other mechanism
     * authenticates the connection without looking at the password.
     */

    @Test
    public void testBindAsUserExternalWrongPassword() throws Exception {
        doTestBindAsUser("EXTERNAL", WRONG_PASSWORD, false);
    }


    @Test
    public void testBindAsUserExternalCorrectPassword() throws Exception {
        doTestBindAsUser("EXTERNAL", PASSWORD, true);
    }


    @Test
    public void testBindAsUserNoneWrongPassword() throws Exception {
        doTestBindAsUser("none", WRONG_PASSWORD, false);
    }


    @Test
    public void testBindAsUserNoneCorrectPassword() throws Exception {
        doTestBindAsUser("none", PASSWORD, true);
    }


    @Test
    public void testBindAsUserDigestWrongPassword() throws Exception {
        doTestBindAsUser("DIGEST-MD5", WRONG_PASSWORD, false);
    }


    @Test
    public void testBindAsUserDigestCorrectPassword() throws Exception {
        doTestBindAsUser("DIGEST-MD5", PASSWORD, true);
    }


    @Test
    public void testBindAsUserGssapiWrongPassword() throws Exception {
        doTestBindAsUser("GSSAPI", WRONG_PASSWORD, false);
    }


    @Test
    public void testBindAsUserGssapiCorrectPassword() throws Exception {
        doTestBindAsUser("GSSAPI", PASSWORD, true);
    }


    @Test
    public void testBindAsUserSimpleWrongPassword() throws Exception {
        doTestBindAsUser("simple", WRONG_PASSWORD, false);
    }


    @Test
    public void testBindAsUserSimpleCorrectPassword() throws Exception {
        doTestBindAsUser("simple", PASSWORD, true);
    }


    @Test
    public void testBindAsUserDefaultWrongPassword() throws Exception {
        doTestBindAsUser(null, WRONG_PASSWORD, false);
    }


    @Test
    public void testBindAsUserDefaultCorrectPassword() throws Exception {
        doTestBindAsUser(null, PASSWORD, true);
    }


    private void doTestBindAsUser(String authentication, String credentials, boolean expected) throws Exception {
        JNDIRealm realm = new JNDIRealm();
        realm.containerLog = LogFactory.getLog(TestJNDIRealmBindAsUser.class);
        realm.setAuthentication(authentication);

        TesterBindDirContext context = new TesterBindDirContext();
        if (authentication != null) {
            context.addToEnvironment(Context.SECURITY_AUTHENTICATION, authentication);
        }

        JNDIRealm.User user = new JNDIRealm.User(USER, USER_DN, null, null, null);

        boolean result = realm.bindAsUser(context, user, credentials);

        Assert.assertEquals(Boolean.valueOf(expected), Boolean.valueOf(result));

        // The user's credentials must always be checked with a simple bind
        Assert.assertEquals(1, context.bindMechanisms.size());
        Assert.assertEquals("simple", context.bindMechanisms.get(0));

        // The originally configured mechanism must be restored and the user's
        // credentials removed
        Hashtable<?,?> env = context.getEnvironment();
        Assert.assertEquals(authentication, env.get(Context.SECURITY_AUTHENTICATION));
        Assert.assertFalse(env.containsKey(Context.SECURITY_PRINCIPAL));
        Assert.assertFalse(env.containsKey(Context.SECURITY_CREDENTIALS));
    }


    private JNDIRealm createRealm(String authentication, boolean usePattern) {
        JNDIRealm realm = new JNDIRealm();
        realm.containerLog = LogFactory.getLog(TestJNDIRealmBindAsUser.class);

        realm.setConnectionURL("ldap://localhost:" + ldapServer.getListenPort());
        realm.setAuthentication(authentication);
        if (usePattern) {
            realm.setUserPattern(USER_PATTERN);
        } else {
            realm.setUserSearch(USER_SEARCH);
            realm.setUserBase(USER_BASE);
        }
        // userPassword is deliberately not set so credentials are validated by
        // binding as the user

        return realm;
    }


    @BeforeClass
    public static void createLDAP() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        InetAddress localhost = InetAddress.getByName("localhost");
        InMemoryListenerConfig listenerConfig =
                new InMemoryListenerConfig("localListener", localhost, 0, null, null, null);
        config.setListenerConfigs(listenerConfig);
        ldapServer = new InMemoryDirectoryServer(config);

        ldapServer.startListening();

        try (LDAPConnection conn =  ldapServer.getConnection()) {

            AddRequest addBase = new AddRequest(
                    "dn: dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: domain",
                    "dc: example");
            LDAPResult result = conn.processOperation(addBase);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());

            AddRequest addPeople = new AddRequest(
                    "dn: ou=people,dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: organizationalUnit");
            result = conn.processOperation(addPeople);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());

            AddRequest addUserTest = new AddRequest(
                    "dn: " + USER_DN,
                    "objectClass: top",
                    "objectClass: person",
                    "objectClass: organizationalPerson",
                    "cn: " + USER,
                    "sn: Test",
                    "userPassword: " + PASSWORD);
            result = conn.processOperation(addUserTest);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());
        }
    }


    @AfterClass
    public static void destroyLDAP() {
        ldapServer.shutDown(true);
    }


    /**
     * Minimal directory context that mimics how a directory server processes a
     * bind. A simple bind (the default when a principal is provided and no
     * mechanism is configured) validates the provided password. Any other
     * mechanism (none, EXTERNAL, DIGEST-MD5, GSSAPI) is treated as succeeding
     * without reference to the provided password since the identity is
     * established by other means (anonymous, TLS client certificate, Kerberos
     * ticket, etc.).
     */
    private static class TesterBindDirContext extends InitialDirContext {

        private final Hashtable<Object,Object> env = new Hashtable<>();
        private final List<String> bindMechanisms = new ArrayList<>();

        TesterBindDirContext() throws NamingException {
            super(true);
        }

        @Override
        public Hashtable<?,?> getEnvironment() throws NamingException {
            return new Hashtable<>(env);
        }

        @Override
        public Object addToEnvironment(String propName, Object propVal) throws NamingException {
            return env.put(propName, propVal);
        }

        @Override
        public Object removeFromEnvironment(String propName) throws NamingException {
            return env.remove(propName);
        }

        @Override
        public Attributes getAttributes(String name, String[] attrIds) throws NamingException {
            Object mechanism = env.get(Context.SECURITY_AUTHENTICATION);
            Object principal = env.get(Context.SECURITY_PRINCIPAL);
            Object credentials = env.get(Context.SECURITY_CREDENTIALS);
            if (mechanism == null && principal != null) {
                // JNDI LDAP provider default
                mechanism = "simple";
            }
            bindMechanisms.add(String.valueOf(mechanism));
            if ("simple".equals(mechanism)) {
                if (!USER_DN.equals(principal) || !PASSWORD.equals(credentials)) {
                    throw new AuthenticationException("[LDAP: error code 49 - Invalid Credentials]");
                }
            }
            // Any other mechanism authenticates without checking the password
            return new BasicAttributes(true);
        }
    }
}
