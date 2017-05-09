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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.junit.Assert.*;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import javax.naming.directory.BasicAttributes;

import hudson.util.Secret;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.FromGroupSearchLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.FromUserRecordLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.LDAPConfiguration;
import jenkins.security.plugins.ldap.LDAPTestConfiguration;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.ldap.LdapUserSearch;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.jvnet.hudson.test.recipes.LocalData;
import org.xml.sax.SAXException;

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

    @Test
    public void configRoundTrip() throws Exception {
        final String server = "ldap.itd.umich.edu";
        final String rootDN = "ou=umich,ou.edu";
        final String userSearchBase = "cn=users,ou=umich,ou.edu";
        final String managerDN = "cn=admin,ou=umich,ou.edu";
        final String managerSecret = "secret";
        final LDAPSecurityRealm realm = new LDAPSecurityRealm(
                server,
                rootDN,
                userSearchBase,
                null,
                null,
                null,
                new FromUserRecordLDAPGroupMembershipStrategy("previousValue"),
                managerDN,
                Secret.fromString(managerSecret),
                false,
                false,
                null,
                null,
                null,
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        r.jenkins.setSecurityRealm(realm);
        final JenkinsRule.WebClient client = r.createWebClient();
        r.submit(client.goTo("configureSecurity").getFormByName("config"));

        LDAPSecurityRealm newRealm = (LDAPSecurityRealm) r.jenkins.getSecurityRealm();
        assertNotSame(realm, newRealm);
        LDAPConfiguration config = newRealm.getConfigurations().get(0);
        assertEquals(server, config.getServer());
        assertEquals(rootDN, config.getRootDN());
        assertEquals(userSearchBase, config.getUserSearchBase());
        assertEquals(managerDN, config.getManagerDN());
        assertEquals(managerSecret, config.getManagerPassword());
        assertThat(newRealm.getUserIdStrategy(), instanceOf(IdStrategy.CaseInsensitive.class));
        assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_USER_SEARCH, config.getUserSearch());
        assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME, config.getDisplayNameAttributeName());
        assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME, config.getMailAddressAttributeName());
    }

    static class TestConf {
        final String server;
        final String rootDN;
        final String userSearchBase;
        final String managerDN;
        final String managerSecret;

        public TestConf(String server, String rootDN, String userSearchBase, String managerDN, String managerSecret) {
            this.server = server;
            this.rootDN = rootDN;
            this.userSearchBase = userSearchBase;
            this.managerDN = managerDN;
            this.managerSecret = managerSecret;
        }
    }

    @Test
    public void configRoundTripTwo() throws Exception {
        TestConf[] confs = new TestConf[2];
        confs[0] = new TestConf("ldap.example.com", "ou=example,ou.com", "cn=users,ou=example,ou.com", "cn=admin,ou=example,ou.com", "secret1");
        confs[1] = new TestConf("ldap2.example.com", "ou=example2,ou.com", "cn=users,ou=example2,ou.com", "cn=admin,ou=example2,ou.com", "secret2");
        List<LDAPConfiguration> ldapConfigurations = new ArrayList<>();
        for (int i = 0; i < confs.length; i++) {
            TestConf conf = confs[i];
            final LDAPConfiguration configuration = new LDAPConfiguration(conf.server, conf.rootDN, false, conf.managerDN, Secret.fromString(conf.managerSecret));
            configuration.setUserSearchBase(conf.userSearchBase);
            ldapConfigurations.add(configuration);
        }
        final LDAPSecurityRealm realm = new LDAPSecurityRealm(ldapConfigurations,
                true,
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        r.jenkins.setSecurityRealm(realm);
        final JenkinsRule.WebClient client = r.createWebClient();
        r.submit(client.goTo("configureSecurity").getFormByName("config"));

        LDAPSecurityRealm newRealm = (LDAPSecurityRealm) r.jenkins.getSecurityRealm();
        assertNotSame(realm, newRealm);
        final List<LDAPConfiguration> configurations = newRealm.getConfigurations();
        assertThat(configurations, hasSize(confs.length));
        for (int i = 0; i < configurations.size(); i++) {
            LDAPConfiguration config = configurations.get(i);
            TestConf conf = confs[i];
            assertEquals(conf.server, config.getServer());
            assertEquals(conf.rootDN, config.getRootDN());
            assertEquals(conf.userSearchBase, config.getUserSearchBase());
            assertEquals(conf.managerDN, config.getManagerDN());
            assertEquals(conf.managerSecret, config.getManagerPassword());
            assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_USER_SEARCH, config.getUserSearch());
            assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME, config.getDisplayNameAttributeName());
            assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME, config.getMailAddressAttributeName());
        }
        assertThat(newRealm.getUserIdStrategy(), instanceOf(IdStrategy.CaseInsensitive.class));
    }

    @Test
    public void configRoundTwoThreeSameName() throws Exception {
        TestConf[] confs = new TestConf[2];
        confs[0] = new TestConf("ldap.example.com", "ou=example,ou.com", "cn=users,ou=example,ou.com", "cn=admin,ou=example,ou.com", "secret1");
        confs[1] = new TestConf("ldap.example.com", "ou=example2,ou.com", "cn=users,ou=example2,ou.com", "cn=admin,ou=example2,ou.com", "secret2");
        List<LDAPConfiguration> ldapConfigurations = new ArrayList<>();
        for (int i = 0; i < confs.length; i++) {
            TestConf conf = confs[i];
            final LDAPConfiguration configuration = new LDAPConfiguration(conf.server, conf.rootDN, false, conf.managerDN, Secret.fromString(conf.managerSecret));
            configuration.setUserSearchBase(conf.userSearchBase);
            ldapConfigurations.add(configuration);
        }
        final LDAPSecurityRealm realm = new LDAPSecurityRealm(ldapConfigurations,
                true,
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        r.jenkins.setSecurityRealm(realm);
        final JenkinsRule.WebClient client = r.createWebClient();
        try {
            r.submit(client.goTo("configureSecurity").getFormByName("config"));
            fail("Should not succeed");
        } catch (FailingHttpStatusCodeException e) {
            assertThat(e.getResponse().getContentAsString(), containsString(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_NotSameServer()));
        }
    }

    @Test
    public void configRoundTripThreeSameName() throws Exception {
        TestConf[] confs = new TestConf[3];
        confs[0] = new TestConf("ldap.example.com", "ou=example,ou.com", "cn=users,ou=example,ou.com", "cn=admin,ou=example,ou.com", "secret1");
        confs[1] = new TestConf("ldap2.example.com", "ou=example2,ou.com", "cn=users,ou=example2,ou.com", "cn=admin,ou=example2,ou.com", "secret2");
        confs[2] = new TestConf("ldap.example.com", "ou=example3,ou.com", "cn=users,ou=example3,ou.com", "cn=admin,ou=example3,ou.com", "secret3");
        List<LDAPConfiguration> ldapConfigurations = new ArrayList<>();
        for (int i = 0; i < confs.length; i++) {
            TestConf conf = confs[i];
            final LDAPConfiguration configuration = new LDAPConfiguration(conf.server, conf.rootDN, false, conf.managerDN, Secret.fromString(conf.managerSecret));
            configuration.setUserSearchBase(conf.userSearchBase);
            ldapConfigurations.add(configuration);
        }
        final LDAPSecurityRealm realm = new LDAPSecurityRealm(ldapConfigurations,
                true,
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        r.jenkins.setSecurityRealm(realm);
        final JenkinsRule.WebClient client = r.createWebClient();
        try {
            r.submit(client.goTo("configureSecurity").getFormByName("config"));
            fail("Should not succeed");
        } catch (FailingHttpStatusCodeException e) {
            assertThat(e.getResponse().getContentAsString(), containsString(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_NotSameServer()));
        }
    }
}
