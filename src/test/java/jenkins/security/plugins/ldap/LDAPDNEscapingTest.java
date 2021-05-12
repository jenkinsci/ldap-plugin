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

import java.io.InputStream;

import java.util.Collections;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.hamcrest.Matchers;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.core.userdetails.UserDetails;
import hudson.model.User;
import hudson.security.LDAPSecurityRealm;
import hudson.security.LDAPSecurityRealm.CacheConfiguration;
import hudson.util.Secret;
import jenkins.model.IdStrategy;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;


/**
 * Tests {@link LDAPConfiguration} with DNs that are not URL safe.
 */
@LDAPTestConfiguration
public class LDAPDNEscapingTest {

    //@Rule
    public LDAPRule ads = new LDAPRule();
    //@Rule
    public JenkinsRule r = new JenkinsRule();

    @Rule
    public RuleChain chain = RuleChain.outerRule(ads).around(r);
    
    @Test
    public void testSpacesInDN() throws Exception {
        /*
         try (InputStream ldifIs = getClass().getResourceAsStream("/jenkins/security/plugins/ldap/LDAPDNEscapingTest/dnWithSpaces.ldif")) {
            ads.loadSchema("default", "dc=com", ldifIs);
        }
         */
        InputStream ldifIs = getClass().getResourceAsStream("/jenkins/security/plugins/ldap/LDAPDNEscapingTest/dnWithSpaces.ldif");
        assertThat(ldifIs, notNullValue());
        ads.loadSchema("planetexpress", "dc=planet express,dc=com", ldifIs);
        //ads.loadSchema("sevenSeas", "o=sevenSeas", getClass().getResourceAsStream("/hudson/security/sevenSeas.ldif"));

        LDAPConfiguration conf = new LDAPConfiguration(
                ads.getUrl(),
                null,
                false,
                "uid=admin,ou=system",
                Secret.fromString("pass"));
        LDAPSecurityRealm realm = new LDAPSecurityRealm(
                Collections.singletonList(conf),
                false,
                new CacheConfiguration(100, 100),
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        r.jenkins.setSecurityRealm(realm);
        
        // check we can get some userDetails about "fry".
        UserDetails userDetails = r.jenkins.getSecurityRealm().loadUserByUsername2("fry");
        assertThat(userDetails, notNullValue());

        // check login works.
        WebClient wc = r.createWebClient().login("professor", "professor"); 
        
        HtmlPage whoAmI = wc.goTo("whoAmI");
        assertThat(whoAmI.asText(), Matchers.containsString("Professor Farnsworth"));
    }

    @Test
    @Issue("JENKINS-12345")
    public void testSpacesInDNWithRootDN() throws Exception {
        /*
         try (InputStream ldifIs = getClass().getResourceAsStream("/jenkins/security/plugins/ldap/LDAPDNEscapingTest/dnWithSpaces.ldif")) {
            ads.loadSchema("default", "dc=com", ldifIs);
        }
         */
        InputStream ldifIs = getClass().getResourceAsStream("/jenkins/security/plugins/ldap/LDAPDNEscapingTest/dnWithSpaces.ldif");
        assertThat(ldifIs, notNullValue());
        ads.loadSchema("planetexpress", "dc=planet express,dc=com", ldifIs);
        //ads.loadSchema("sevenSeas", "o=sevenSeas", getClass().getResourceAsStream("/hudson/security/sevenSeas.ldif"));

        LDAPConfiguration conf = new LDAPConfiguration(
                ads.getUrl(),
                "dc=planet express,dc=com",
                false,
                "uid=admin,ou=system",
                Secret.fromString("pass"));
        LDAPSecurityRealm realm = new LDAPSecurityRealm(
                Collections.singletonList(conf),
                false,
                new CacheConfiguration(100, 100),
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        r.jenkins.setSecurityRealm(realm);
        
        // check we can get some userDetails about "fry".
        UserDetails userDetails = r.jenkins.getSecurityRealm().loadUserByUsername2("fry");
        assertThat(userDetails, notNullValue());

        // check login works.
        WebClient wc = r.createWebClient().login("professor", "professor"); 
        
        HtmlPage whoAmI = wc.goTo("whoAmI");
        assertThat(whoAmI.asText(), Matchers.containsString("Professor Farnsworth"));
    }

}