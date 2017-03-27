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

import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import javax.naming.directory.BasicAttributes;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.FromGroupSearchLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.FromUserRecordLDAPGroupMembershipStrategy;
import junit.framework.TestCase;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.ldap.LdapUserSearch;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import jenkins.security.plugins.ldap.LDAPConfiguration;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

public class LDAPSecurityRealmTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();

    /**
     * This minimal test still causes the 'LDAPBindSecurityRealm.groovy' to be parsed, allowing us to catch
     * basic syntax errors and such.
     */
    @Test
    public void groovyBeanDef() {
        r.jenkins.setSecurityRealm(new LDAPSecurityRealm("ldap.itd.umich.edu", null, null, null, null, null, null, false));
        System.out.println(r.jenkins.getSecurityRealm().getSecurityComponents());// force the component creation
    }

    @Test
    public void sessionStressTest() {
        LDAPSecurityRealm.LDAPUserDetailsService s = new LDAPSecurityRealm.LDAPUserDetailsService(
                new LdapUserSearch() {
                    @Override
                    public LdapUserDetails searchForUser(String username) {
                        LdapUserDetailsImpl.Essence e = new LdapUserDetailsImpl.Essence();
                        e.setUsername((String) username);
                        BasicAttributes ba = new BasicAttributes();
                        ba.put("test", username);
                        ba.put("xyz", "def");
                        e.setAttributes(ba);
                        return e.createUserDetails();
                    }
                },
                new LdapAuthoritiesPopulator() {
                    @Override
                    public GrantedAuthority[] getGrantedAuthorities(LdapUserDetails userDetails)
                            throws LdapDataAccessException {
                        return new GrantedAuthority[0];
                    }
                }
        );
        LdapUserDetails d1 = s.loadUserByUsername("me");
        LdapUserDetails d2 = s.loadUserByUsername("you");
        LdapUserDetails d3 = s.loadUserByUsername("me");
        // caching should reuse the same attributes
        assertSame(d1.getAttributes(), d3.getAttributes());
        assertNotSame(d1.getAttributes(), d2.getAttributes());
    }

    @LocalData
    @Test
    public void compatAndConfig() throws Exception {
        check();
        r.configRoundtrip();
        check();
    }

    private void check() {
        LDAPSecurityRealm sr = (LDAPSecurityRealm) r.jenkins.getSecurityRealm();
        LDAPConfiguration cnf = sr.getConfigurationFor("s");
        assertEquals("s", cnf.getServer());
        assertEquals("rDN", cnf.getRootDN());
        assertEquals("uSB", cnf.getUserSearchBase());
        assertEquals("uS", cnf.getUserSearch());
        assertEquals("gSB", cnf.getGroupSearchBase());
        assertEquals("gSF", cnf.getGroupSearchFilter());
        assertThat(cnf.getGroupMembershipStrategy(), instanceOf(FromGroupSearchLDAPGroupMembershipStrategy.class));
        assertThat(((FromGroupSearchLDAPGroupMembershipStrategy)cnf.getGroupMembershipStrategy()).getFilter(), is("gMF"));
        assertNull(sr.groupMembershipFilter);
        assertEquals("mDN", cnf.getManagerDN());
        assertEquals("s3cr3t", cnf.getManagerPassword());
        assertTrue(cnf.isInhibitInferRootDN());
        assertTrue(sr.disableMailAddressResolver);
        assertEquals(Integer.valueOf(20), sr.getCacheSize());
        assertEquals(Integer.valueOf(60), sr.getCacheTTL());
        assertEquals(Collections.singletonMap("k", "v"), cnf.getExtraEnvVars());
        assertEquals("dNAN", cnf.getDisplayNameAttributeName());
        assertEquals("mAAN", cnf.getMailAddressAttributeName());
    }

    @Issue("JENKINS-8152")
    @WithoutJenkins
    @Test
    public void providerUrl() throws Exception {
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

    @Issue("JENKINS-30588")
    @Test
    public void groupMembershipAttribute() throws Exception {
        final String previousValue = "previousValue";
        final String testValue = "testValue";
        final LDAPSecurityRealm realm = new LDAPSecurityRealm(
                "ldap.itd.umich.edu",
                null,
                null,
                null,
                null,
                null,
                new FromUserRecordLDAPGroupMembershipStrategy("previousValue"),
                null,
                null,
                false,
                false,
                null,
                null,
                null,
                null,
                (IdStrategy)null,
                (IdStrategy)null);
        r.jenkins.setSecurityRealm(realm);
        r.jenkins.getSecurityRealm().createSecurityComponents();
        final JenkinsRule.WebClient c = r.createWebClient();
        final HtmlPage security = c.goTo("configureSecurity");
        final HtmlForm form = security.getFormByName("config");
        getButtonByText(form, "Advanced...").click();
        for (HtmlInput e : form.getInputsByName("_.attributeName")) {
            if (e.getValueAttribute().equals(previousValue)) {
                e.setValueAttribute(testValue);
            }
        }
        getButtonByText(form, "Save").click();
        final LDAPSecurityRealm changedRealm = ((LDAPSecurityRealm)r.jenkins.getSecurityRealm());
        final LDAPConfiguration conf = changedRealm.getConfigurations().get(0);
        final String changedValue = ((FromUserRecordLDAPGroupMembershipStrategy)conf.getGroupMembershipStrategy()).getAttributeName();
        assertEquals("Value should be changed", testValue, changedValue);
    }

    private HtmlButton getButtonByText(HtmlForm form, String text) throws Exception {
        for (HtmlElement e : form.getElementsByTagName("button")) {
            if (text.equals(e.getTextContent())) {
                return ((HtmlButton)e);
            }
        }
        throw new AssertionError(String.format("Button [%s] not found", text));
    }

}
