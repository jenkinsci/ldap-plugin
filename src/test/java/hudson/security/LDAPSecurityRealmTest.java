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

import java.util.ArrayList;
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

import hudson.util.Secret;
import javax.naming.InvalidNameException;
import javax.naming.directory.BasicAttributes;
import javax.naming.ldap.LdapName;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.*;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.jvnet.hudson.test.recipes.LocalData;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class LDAPSecurityRealmTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();

    @Test
    public void attributesCache() {
        LDAPSecurityRealm.LDAPUserDetailsService s = new LDAPSecurityRealm.LDAPUserDetailsService(
            username -> {
                BasicAttributes ba = new BasicAttributes();
                ba.put("test", username);
                ba.put("xyz", "def");
                try {
                    return new DirContextAdapter(ba, new LdapName("dn=" + username));
                } catch (InvalidNameException x) {
                    throw new UsernameNotFoundException(x.toString(), x);
                }
            }, (userData, username) -> Collections.emptySet(), null, "irrelevant");
        LDAPSecurityRealm.DelegatedLdapUserDetails d1 = s.loadUserByUsername("me");
        LDAPSecurityRealm.DelegatedLdapUserDetails d2 = s.loadUserByUsername("you");
        LDAPSecurityRealm.DelegatedLdapUserDetails d3 = s.loadUserByUsername("me");
        // caching should reuse the same attributes
        assertSame(LDAPSecurityRealm.DelegatedLdapUserDetails.getAttributes(d1, null), LDAPSecurityRealm.DelegatedLdapUserDetails.getAttributes(d3, null));
        assertNotSame(LDAPSecurityRealm.DelegatedLdapUserDetails.getAttributes(d1, null), LDAPSecurityRealm.DelegatedLdapUserDetails.getAttributes(d2, null));
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
        LDAPConfiguration cnf = sr.getConfigurations().get(0);
        assertEquals("s", cnf.getServer());
        assertTrue(cnf.isSslVerify());
        assertEquals("rDN=x", cnf.getRootDN());
        assertEquals("uSB", cnf.getUserSearchBase());
        assertEquals("uS", cnf.getUserSearch());
        assertEquals("gSB", cnf.getGroupSearchBase());
        assertEquals("gSF", cnf.getGroupSearchFilter());
        assertThat(cnf.getGroupMembershipStrategy(), instanceOf(FromGroupSearchLDAPGroupMembershipStrategy.class));
        assertThat(((FromGroupSearchLDAPGroupMembershipStrategy) cnf.getGroupMembershipStrategy()).getFilter(), is("gMF"));
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
                (IdStrategy) null,
                (IdStrategy) null);
        r.jenkins.setSecurityRealm(realm);
        r.jenkins.getSecurityRealm().createSecurityComponents();
        final JenkinsRule.WebClient c = r.createWebClient();
        final HtmlPage security = c.goTo("configureSecurity");
        final HtmlForm form = security.getFormByName("config");
        getButtonByText(form, "Advanced Server Configuration...").click();
        for (HtmlInput e : form.getInputsByName("_.attributeName")) {
            if (e.getValueAttribute().equals(previousValue)) {
                e.setValueAttribute(testValue);
            }
        }
        getButtonByText(form, "Save").click();
        final LDAPSecurityRealm changedRealm = ((LDAPSecurityRealm) r.jenkins.getSecurityRealm());
        final LDAPConfiguration conf = changedRealm.getConfigurations().get(0);
        final String changedValue = ((FromUserRecordLDAPGroupMembershipStrategy) conf.getGroupMembershipStrategy()).getAttributeName();
        assertEquals("Value should be changed", testValue, changedValue);
    }

    private HtmlButton getButtonByText(HtmlForm form, String text) throws Exception {
        for (HtmlElement e : form.getElementsByTagName("button")) {
            if (text.equals(e.getTextContent())) {
                return ((HtmlButton) e);
            }
        }
        throw new AssertionError(String.format("Button [%s] not found", text));
    }

    @Test
    public void configRoundTrip() throws Exception {
        final String server = "ldap.itd.umich.edu";
        final String rootDN = "ou=umich,dc=ou.edu";
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
        assertTrue(config.isSslVerify());
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
        confs[0] = new TestConf("ldap.example.com", "ou=example,dc=ou.com", "cn=users,ou=example,ou.com", "cn=admin,ou=example,ou.com", "secret1");
        confs[1] = new TestConf("ldap2.example.com", "ou=example2,dc=ou.com", "cn=users,ou=example2,ou.com", "cn=admin,ou=example2,ou.com", "secret2");
        List<LDAPConfiguration> ldapConfigurations = new ArrayList<>();
        for (int i = 0; i < confs.length; i++) {
            TestConf conf = confs[i];
            final LDAPConfiguration configuration = new LDAPConfiguration(conf.server, conf.rootDN, false, conf.managerDN, Secret.fromString(conf.managerSecret));
            configuration.setUserSearchBase(conf.userSearchBase);
            configuration.setIgnoreIfUnavailable(i % 2 == 0);
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
            assertTrue(config.isSslVerify());
            assertEquals(conf.rootDN, config.getRootDN());
            assertEquals(conf.userSearchBase, config.getUserSearchBase());
            assertEquals(conf.managerDN, config.getManagerDN());
            assertEquals(conf.managerSecret, config.getManagerPassword());
            assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_USER_SEARCH, config.getUserSearch());
            assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME, config.getDisplayNameAttributeName());
            assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME, config.getMailAddressAttributeName());
            assertEquals(i % 2 == 0, config.isIgnoreIfUnavailable());
        }
        assertThat(newRealm.getUserIdStrategy(), instanceOf(IdStrategy.CaseInsensitive.class));
    }

    @Test
    public void configRoundTwoThreeSameId() throws Exception {
        TestConf[] confs = new TestConf[2];
        confs[0] = new TestConf("ldap.example.com", "ou=example,dc=ou.com", "cn=users,ou=example,ou.com", "cn=admin,ou=example,ou.com", "secret1");
        confs[1] = new TestConf("ldap.example.com", "ou=example,dc=ou.com", "cn=users,ou=example,ou.com", "cn=admin,ou=example2,ou.com", "secret2");
        List<LDAPConfiguration> ldapConfigurations = new ArrayList<>();
        for (int i = 0; i < confs.length; i++) {
            TestConf conf = confs[i];
            final LDAPConfiguration configuration = new LDAPConfiguration(conf.server, conf.rootDN, false, conf.managerDN, Secret.fromString(conf.managerSecret));
            configuration.setUserSearchBase(conf.userSearchBase);
            ldapConfigurations.add(configuration);
        }
        try {
            final LDAPSecurityRealm realm = new LDAPSecurityRealm(ldapConfigurations,
                    true,
                    null,
                    IdStrategy.CASE_INSENSITIVE,
                    IdStrategy.CASE_INSENSITIVE);
            r.jenkins.setSecurityRealm(realm);
            fail("Should have thrown exception");
        } catch (IllegalArgumentException e) {
            //Expected
            try {
                System.setProperty(LDAPSecurityRealm.class.getName() + "do a bad thing during testing", "true");
                LDAPSecurityRealm realm = new LDAPSecurityRealm(ldapConfigurations,
                        true,
                        null,
                        IdStrategy.CASE_INSENSITIVE,
                        IdStrategy.CASE_INSENSITIVE);
                r.jenkins.setSecurityRealm(realm);
            } finally {
                System.setProperty(LDAPSecurityRealm.class.getName() + "do a bad thing during testing", "");
            }
        }
        final JenkinsRule.WebClient client = r.createWebClient();
        try {
            r.submit(client.goTo("configureSecurity").getFormByName("config"));
            fail("Should not succeed");
        } catch (FailingHttpStatusCodeException e) {
            assertThat(e.getResponse().getContentAsString(), containsString(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_NotSameServer()));
        }
    }

    @Test
    public void configRoundTripThreeSameId() throws Exception {
        TestConf[] confs = new TestConf[3];
        confs[0] = new TestConf("ldap.example.com", "ou=example,dc=ou.com", "cn=users,ou=example,ou.com", "cn=admin,ou=example,ou.com", "secret1");
        confs[1] = new TestConf("ldap2.example.com", "ou=example2,dc=ou.com", "cn=users,ou=example2,ou.com", "cn=admin,ou=example2,ou.com", "secret2");
        confs[2] = new TestConf("ldap.example.com", "ou=example,dc=ou.com", "cn=users,ou=example,ou.com", "cn=admin,ou=example3,ou.com", "secret3");
        List<LDAPConfiguration> ldapConfigurations = new ArrayList<>();
        for (int i = 0; i < confs.length; i++) {
            TestConf conf = confs[i];
            final LDAPConfiguration configuration = new LDAPConfiguration(conf.server, conf.rootDN, false, conf.managerDN, Secret.fromString(conf.managerSecret));
            configuration.setUserSearchBase(conf.userSearchBase);
            ldapConfigurations.add(configuration);
        }
        try {
            LDAPSecurityRealm realm = new LDAPSecurityRealm(ldapConfigurations,
                    true,
                    null,
                    IdStrategy.CASE_INSENSITIVE,
                    IdStrategy.CASE_INSENSITIVE);
            r.jenkins.setSecurityRealm(realm);
            fail("Should have thrown exception");
        } catch (IllegalArgumentException e) {
            //Expected
            try {
                System.setProperty(LDAPSecurityRealm.class.getName() + "do a bad thing during testing", "true");
                LDAPSecurityRealm realm = new LDAPSecurityRealm(ldapConfigurations,
                        true,
                        null,
                        IdStrategy.CASE_INSENSITIVE,
                        IdStrategy.CASE_INSENSITIVE);
                r.jenkins.setSecurityRealm(realm);
            } finally {
                System.setProperty(LDAPSecurityRealm.class.getName() + "do a bad thing during testing", "");
            }

        }
        final JenkinsRule.WebClient client = r.createWebClient();
        try {
            r.submit(client.goTo("configureSecurity").getFormByName("config"));
            fail("Should not succeed");
        } catch (FailingHttpStatusCodeException e) {
            assertThat(e.getResponse().getContentAsString(), containsString(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_NotSameServer()));
        }
    }

    @Test
    public void configRoundTripEnvironmentProperties() throws Exception {
        final String server = "ldap.itd.umich.edu";
        final String rootDN = "ou=umich,dc=ou.edu";
        final String userSearchBase = "cn=users,ou=umich,ou.edu";
        final String managerDN = "cn=admin,ou=umich,ou.edu";
        final String managerSecret = "secret";

        LDAPConfiguration c = new LDAPConfiguration(server, rootDN, false, managerDN, Secret.fromString(managerSecret));

        LDAPSecurityRealm.EnvironmentProperty[] environmentProperties = {new LDAPSecurityRealm.EnvironmentProperty("java.naming.ldap.typesOnly", "true")};
        c.setEnvironmentProperties(environmentProperties);
        c.setUserSearchBase(userSearchBase);

        List<LDAPConfiguration> configurations = new ArrayList<LDAPConfiguration>();
        configurations.add(c);
        LDAPSecurityRealm realm = new LDAPSecurityRealm(
                configurations,
                false,
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE
        );

        r.jenkins.setSecurityRealm(realm);

        final JenkinsRule.WebClient client = r.createWebClient();
        r.submit(client.goTo("configureSecurity").getFormByName("config"));

        LDAPSecurityRealm newRealm = (LDAPSecurityRealm) r.jenkins.getSecurityRealm();
        assertNotSame(realm, newRealm);
        LDAPConfiguration newConfig = newRealm.getConfigurations().get(0);
        assertEquals(server, newConfig.getServer());
        assertTrue(newConfig.isSslVerify());
        assertEquals(rootDN, newConfig.getRootDN());
        assertEquals(userSearchBase, newConfig.getUserSearchBase());
        assertEquals(managerDN, newConfig.getManagerDN());
        assertEquals(managerSecret, newConfig.getManagerPassword());
        assertThat(newRealm.getUserIdStrategy(), instanceOf(IdStrategy.CaseInsensitive.class));
        assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_USER_SEARCH, newConfig.getUserSearch());
        assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME, newConfig.getDisplayNameAttributeName());
        assertEquals(LDAPSecurityRealm.DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME, newConfig.getMailAddressAttributeName());
        assertTrue(newConfig.getEnvironmentProperties().length > 0);
        assertEquals(newConfig.getEnvironmentProperties()[0].getName(), c.getEnvironmentProperties()[0].getName());
        assertEquals(newConfig.getEnvironmentProperties()[0].getValue(), c.getEnvironmentProperties()[0].getValue());
    }

}
