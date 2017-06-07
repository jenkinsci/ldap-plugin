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
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;

import static org.hamcrest.CoreMatchers.containsString;
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

}