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
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.junit.runner.RunWith;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.springframework.security.core.userdetails.UserDetails;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import hudson.security.GroupDetails;
import hudson.security.LDAPSecurityRealm;
import hudson.util.Secret;
import jenkins.model.IdStrategy;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;

/**
 * Tests {@link LDAPConfiguration} with DNs that are not URL safe.
 */
@LDAPTestConfiguration
@RunWith(JUnitParamsRunner.class)
public class LDAPDNEscapingTest {

    @ClassRule
    public static LDAPRule ads = new LDAPRule();

    @Rule
    public JenkinsRule r = new JenkinsRule();


    @BeforeClass
    public static void setupLdap() throws Exception {
        try (InputStream ldifIs = LDAPDNEscapingTest.class.getResourceAsStream("/jenkins/security/plugins/ldap/LDAPDNEscapingTest/dnWithSpaces.ldif")) {
            ads.loadSchema("planetexpress", "dc=planet express,dc=com", ldifIs);
       }
    }

    // here as eclipse can not run a single parameterized test as it does not support the custom JUnitParamsRunner
    /*
    @Test
    public void testSpacesInDN() throws Exception {
        testOrgEscaping("dc=planet express,dc=com", null, null);
    }
    */

    @Test
    @Issue("JENKINS-12345")
    @Parameters
    public void testOrgEscaping(String rootDN, String userSearchBase, String groupSearchBase) throws Exception {

        LDAPConfiguration conf = new LDAPConfiguration(
                ads.getUrl(),
                rootDN,
                false,
                "uid=admin,ou=system",
                Secret.fromString("pass"));
        conf.setUserSearchBase(userSearchBase);
        conf.setGroupSearchBase(groupSearchBase);

        LDAPSecurityRealm realm = new LDAPSecurityRealm(
                Collections.singletonList(conf),
                false,
                null, // no caching new CacheConfiguration(100, 100),
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);

        r.jenkins.setSecurityRealm(realm);
        
        // check we can get some userDetails about "fry".
        UserDetails userDetails = r.jenkins.getSecurityRealm().loadUserByUsername2("fry");
        assertThat("failed to find user fry", userDetails, notNullValue());

        // and a group
        GroupDetails groupDetails = r.jenkins.getSecurityRealm().loadGroupByGroupname2("crew", true);
        assertThat("failed to find group staff", groupDetails, notNullValue());
        assertThat("failed to obtain users for group staff", groupDetails.getMembers(), hasSize(3));

        // check login works (different user and a group that fry is not a member of)
        WebClient wc = r.createWebClient().login("professor", "professor"); 
        
        HtmlPage whoAmI = wc.goTo("whoAmI");
        assertThat(whoAmI.asText(), allOf(containsString("Professor Farnsworth"), // user is loaded 
                                          containsString("management"))); // groups are recognized
    }

    @SuppressWarnings("unused")
    public Object[] parametersForTestOrgEscaping() {
        return new Object[] {
                  // DN, user search base, group search base
                  new Object[] { null, null, null },
                  new Object[] { "dc=planet express,dc=com", null, null },
                  new Object[] { null, "dc=planet express,dc=com", null },
                  new Object[] { null, null, "dc=planet express,dc=com" },
                  new Object[] { "dc=com", "dc=planet express", "dc=planet express" }
                  };
    }
}
