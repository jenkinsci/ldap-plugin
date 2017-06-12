/*
 * The MIT License
 *
 * Copyright (c) 2017 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package jenkins.security.plugins.ldap;

import hudson.security.LDAPSecurityRealm;
import jenkins.model.IdStrategy;
import org.hamcrest.CoreMatchers;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;

import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.collection.IsArrayWithSize.arrayWithSize;
import static org.junit.Assert.*;

/**
 * Tests {@link LDAPConfiguration}.
 */
public class LDAPConfigurationTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();

    @Test
    public void createApplicationContextNoCustomBinding() throws Exception {
        LDAPSecurityRealm realm = new LDAPSecurityRealm("ldap.example.com",
                "",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                true,
                true,
                null,
                null,
                null,
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        r.jenkins.setSecurityRealm(realm);

        r.jenkins.getRootPath().child(LDAPConfiguration.SECURITY_REALM_LDAPBIND_GROOVY).write("throw new IllegalStateException('You stink!')", Charset.defaultCharset().name());
        LDAPConfiguration configuration = realm.getConfigurations().get(0);

        //Should fail when loaded
        try {
            configuration.createApplicationContext(realm, true);
            fail("Should not be able to load that binding");
        } catch (IllegalStateException e) {
            assertEquals("You stink!", e.getMessage());
        }
        final ByteArrayOutputStream logg = new ByteArrayOutputStream();
        LDAPSecurityRealm.LOGGER.addHandler(new StreamHandler(logg, new SimpleFormatter()){
            @Override
            public synchronized void publish(LogRecord record) {
                super.publish(record);
                flush();
            }
        });
        //Should avoid loading when told to
        assertNotNull(configuration.createApplicationContext(realm, false));
        assertThat(new String(logg.toByteArray()), containsString("Not loading custom " + LDAPConfiguration.SECURITY_REALM_LDAPBIND_GROOVY));
    }

    @Test
    public void getId() {
        LDAPConfiguration c = new LDAPConfiguration("ldap.example.com", "dc=example,dc=com", true, null, null);
        String id = c.getId();
        c = new LDAPConfiguration("ldap.example.com", "dc=example,dc=com", true, null, null); //Same so far
        c.setUserSearchBase("cn=users,dc=example,dc=com");
        String id2 = c.getId();
        c = new LDAPConfiguration("ldap.example.com", "dc=example,dc=com", true, null, null); //Same so far
        c.setUserSearchBase("cn=users,dc=example,dc=com"); //Same so far
        c.setUserSearch("sAMAccountName={}");
        String id3 = c.getId();

        c = new LDAPConfiguration("ldap.example.com", "dc=example,dc=com", true, null, null); //Same so far
        c.setUserSearchBase("cn=users,dc=example,dc=com"); //Same so far
        c.setUserSearch("sAMAccountName={}"); //Same as well
        String id3Ident = c.getId(); //New instance with same data as id3

        c = new LDAPConfiguration("ldap://ldap.example.com:389", "dc=example,dc=com", true, null, null); //Same but different
        c.setUserSearchBase("cn=users,dc=example,dc=com"); //Same so far
        c.setUserSearch("sAMAccountName={}"); //New instance with same but different data as id3
        String id3IdentButDifferent = c.getId();

        assertNotEquals(id, id2);
        assertNotEquals(id, id3);
        assertNotEquals(id2, id3);
        assertEquals(id3, id3Ident);
        assertEquals(id3, id3IdentButDifferent);
    }

    @Test
    public void generateId() {
        String id1 = LDAPConfiguration.generateId("ldap.example.com ldap://ad.example.com ldaps://ad2.example.com", "dc=example,dc=com", "cn=users,dc=example,dc=com", null);
        String id2 = LDAPConfiguration.generateId("ldap://ldap.example.com ad.example.com ldaps://ad2.example.com", "dc=example,dc=com", "cn=users,dc=example,dc=com", LDAPConfiguration.LDAPConfigurationDescriptor.DEFAULT_USER_SEARCH);
        String id3 = LDAPConfiguration.generateId("ad.example.com ldaps://ad2.example.com ldap://ldap.example.com ", "dc=example,dc=com", "cn=users,dc=example,dc=com", null);

        String idDiff = LDAPConfiguration.generateId("ad.example.com ldaps://ad2.example.com ldap://ldap.example.com ", "dc=example2,dc=com", "cn=users,dc=example,dc=com", null);

        assertEquals(id1, id2);
        assertEquals(id1, id3);
        assertEquals(id2, id3);

        assertNotEquals(id1, idDiff);
    }

    @Test
    public void generateIdJustOneServer() {
        String id1 = LDAPConfiguration.generateId("ldap.example.com", "dc=example,dc=com", "cn=users,dc=example,dc=com", null);
        String id2 = LDAPConfiguration.generateId("ldap://ldap.example.com", "dc=example,dc=com", "cn=users,dc=example,dc=com", LDAPConfiguration.LDAPConfigurationDescriptor.DEFAULT_USER_SEARCH);
        String id3 = LDAPConfiguration.generateId("ldap://ldap.example.com:389 ", "dc=example,dc=com", "cn=users,dc=example,dc=com", null);

        String idDiff = LDAPConfiguration.generateId("ldap.example.com ", "dc=example2,dc=com", "cn=users,dc=example,dc=com", null);

        assertEquals(id1, id2);
        assertEquals(id1, id3);
        assertEquals(id2, id3);

        assertNotEquals(id1, idDiff);
    }

    @Test
    public void generateIdWithNormalizedUserSearchBase() {
        String id1 = LDAPConfiguration.generateId("ldap.example.com", "dc=example,dc=com", "dc=users,dc=example,dc=com", null);
        String id2 = LDAPConfiguration.generateId("ldap.example.com", "dc=example,dc=com", "dc=users", null);
        String id3 = LDAPConfiguration.generateId("ldap.example.com", "dc=com", "dc=users,dc=example", null);
        String id4 = LDAPConfiguration.generateId("ldap.example.com", null, "dc=users,dc=example,dc=com", null);
        String id5 = LDAPConfiguration.generateId("ldap.example.com", "", "dc=users,dc=example,dc=com", null);
        String id6 = LDAPConfiguration.generateId("ldap.example.com", "dc=users,dc=example,dc=com", "", null);
        String id7 = LDAPConfiguration.generateId("ldap.example.com", "dc=users,dc=example,dc=com", null, null);

        assertEquals(id1, id2);
        assertEquals(id1, id3);
        assertEquals(id1, id4);
        assertEquals(id1, id5);
        assertEquals(id1, id6);
        assertEquals(id1, id7);

        id1 = LDAPConfiguration.generateId("ldap.example.com", "dc=example,dc=com", "dc=users", null);
        id2 = LDAPConfiguration.generateId("ldap.example.com", "dc=example,dc=com", "dc=expats", null);

        assertNotEquals(id1, id2);
    }

    @Test
    public void normalizeServerSameButDifferent() {
        String s1 = "ldap.example.com ldap://ad.example.com ldaps://ad2.example.com";
        String s2 = "ldap://ldap.example.com ad.example.com ldaps://ad2.example.com";
        assertNotEquals(s1, s2); //Duh
        String n1 = LDAPConfiguration.normalizeServer(s1);
        String n2 = LDAPConfiguration.normalizeServer(s2);
        assertEquals(n1, n2);
        assertThat(n1.split("\\s+"), arrayWithSize(s1.split("\\s+").length));
    }

    @Test
    public void normalizeServerSameButDifferentOrder() {
        String s1 = "ad2.example.com b.example.com ad.example.com";
        String s2 = "ad.example.com b.example.com ad2.example.com ";
        assertNotEquals(s1, s2); //Duh
        String n1 = LDAPConfiguration.normalizeServer(s1);
        String n2 = LDAPConfiguration.normalizeServer(s2);
        assertEquals(n1, n2);
        assertThat(n1.split("\\s+"), arrayWithSize(s1.split("\\s+").length));
    }

}