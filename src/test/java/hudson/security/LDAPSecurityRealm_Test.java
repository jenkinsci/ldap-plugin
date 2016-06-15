/*
 * The MIT License
 *
 * Copyright 2014 Jesse Glick.
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

package hudson.security;

import java.util.Collections;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import jenkins.security.plugins.ldap.FromGroupSearchLDAPGroupMembershipStrategy;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

public class LDAPSecurityRealm_Test { // different name so as not to clash with LDAPSecurityRealmTest.groovy

    @Rule public JenkinsRule r = new JenkinsRule();

    @LocalData
    @Test public void compatAndConfig() throws Exception {
        check();
        r.configRoundtrip();
        check();
    }

    private void check() {
        LDAPSecurityRealm sr = (LDAPSecurityRealm) r.jenkins.getSecurityRealm();
        assertEquals("s", sr.server);
        assertEquals("rDN", sr.rootDN);
        assertEquals("uSB", sr.userSearchBase);
        assertEquals("uS", sr.userSearch);
        assertEquals("gSB", sr.groupSearchBase);
        assertEquals("gSF", sr.groupSearchFilter);
        assertThat(sr.getGroupMembershipStrategy(), instanceOf(FromGroupSearchLDAPGroupMembershipStrategy.class));
        assertThat(((FromGroupSearchLDAPGroupMembershipStrategy)sr.getGroupMembershipStrategy()).getFilter(), is("gMF"));
        assertNull(sr.groupMembershipFilter);
        assertEquals("mDN", sr.managerDN);
        assertEquals("s3cr3t", sr.getManagerPassword());
        assertTrue(sr.inhibitInferRootDN);
        assertTrue(sr.disableMailAddressResolver);
        assertEquals(Integer.valueOf(20), sr.getCacheSize());
        assertEquals(Integer.valueOf(60), sr.getCacheTTL());
        assertEquals(Collections.singletonMap("k", "v"), sr.getExtraEnvVars());
        assertEquals("dNAN", sr.getDisplayNameAttributeName());
        assertEquals("mAAN", sr.getMailAddressAttributeName());
    }

    @Issue("JENKINS-8152")
    @WithoutJenkins
    @Test public void providerUrl() throws Exception {
        assertEquals("ldap://example.com/", LDAPSecurityRealm.toProviderUrl("example.com", null));
        assertEquals("ldap://example.com/", LDAPSecurityRealm.toProviderUrl("example.com", ""));
        assertEquals("ldap://example.com/", LDAPSecurityRealm.toProviderUrl("example.com", "   "));
        assertEquals("ldap://example.com/ ldap://example.net/", LDAPSecurityRealm.toProviderUrl("example.com ldap://example.net", null));
        assertEquals("ldap://example.com/o=O,c=C", LDAPSecurityRealm.toProviderUrl("example.com", "o=O,c=C"));
        assertEquals("ldap://example.com/o=O,c=C", LDAPSecurityRealm.toProviderUrl("example.com", "  o=O,c=C"));
        assertEquals("ldap://example.com/o=O,c=C ldap://example.net/o=O,c=C", LDAPSecurityRealm.toProviderUrl("ldap://example.com example.net", "o=O,c=C"));
        assertEquals("ldap://example.com/o=O%20O,c=C", LDAPSecurityRealm.toProviderUrl("example.com", "o=O O,c=C"));
        assertEquals("ldap://example.com/o=O%20O,c=C ldap://example.net/o=O%20O,c=C", LDAPSecurityRealm.toProviderUrl("example.com example.net", "o=O O,c=C  "));
    }

}
