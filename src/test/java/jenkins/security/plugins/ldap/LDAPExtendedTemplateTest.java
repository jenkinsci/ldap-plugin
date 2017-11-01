/*
 * The MIT License
 *
 * Copyright 2017 CloudBees, Inc.
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
import hudson.security.LDAPSecurityRealm.CacheConfiguration;
import hudson.util.Secret;
import java.util.Arrays;
import java.util.List;
import javax.naming.directory.Attributes;
import jenkins.model.IdStrategy;
import org.acegisecurity.ldap.LdapEntryMapper;
import org.junit.Test;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

@LDAPTestConfiguration
public class LDAPExtendedTemplateTest {

    public LDAPRule ads = new LDAPRule();
    public JenkinsRule r = new JenkinsRule();
    @Rule
    public RuleChain chain = RuleChain.outerRule(ads).around(r);

    public LDAPExtendedTemplate template;

    @Before
    public void setup() throws Exception {
        ads.loadSchema("sevenSeas", "o=sevenSeas", getClass().getResourceAsStream("/hudson/security/sevenSeas.ldif"));
        LDAPConfiguration conf = new LDAPConfiguration(
                ads.getUrl(),
                null,
                false,
                "uid=admin,ou=system", Secret.fromString("pass"));
        LDAPSecurityRealm realm = new LDAPSecurityRealm(
                Arrays.asList(conf),
                false,
                new CacheConfiguration(100, 100),
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        r.jenkins.setSecurityRealm(realm);
        template = conf.getLdapTemplate();
    }

    @Test
    public void searchForFirstEntry() throws Exception {
        String matchingDn = (String)template.searchForFirstEntry("", "(cn={0})", new String[]{"Horatio Hornblower"},
                null, new DnEntryMapper());
        assertThat(matchingDn, is("cn=Horatio Hornblower,ou=people,o=sevenSeas"));
    }

    @Test
    public void searchForFirstEntry_noMatch() throws Exception {
        String matchingDn = (String)template.searchForFirstEntry("", "(cn={0})", new String[]{"does not exist"}, null,
                new DnEntryMapper());
        assertThat(matchingDn, nullValue());
    }

    @Test
    public void searchForAllEntries() throws Exception {
        List<String> matchingEntries = (List)template.searchForAllEntries("", "(memberOf={0})",
                new String[]{"cn=HMS_Lydia,ou=crews,ou=groups,o=sevenSeas"}, null, new DnEntryMapper());
        assertThat(matchingEntries, containsInAnyOrder(
                "cn=Horatio Hornblower,ou=people,o=sevenSeas",
                "cn=William Bush,ou=people,o=sevenSeas",
                "cn=Thomas Quist,ou=people,o=sevenSeas",
                "cn=Moultrie Crystal,ou=people,o=sevenSeas"));
    }

    @Test
    public void searchForAllEntries_noMatch() throws Exception {
        List<String> matchingEntries = (List)template.searchForAllEntries("", "(memberOf={0})",
                new String[]{"does not exist"}, null, new DnEntryMapper());
        assertThat(matchingEntries, empty());
    }

    private static class DnEntryMapper implements LdapEntryMapper {
        @Override
        public Object mapAttributes(String dn, Attributes attributes) {
            return dn;
        }
    }

}
