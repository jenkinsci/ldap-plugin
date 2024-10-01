/*
 * The MIT License
 *
 * Copyright 2017 CloudBees,Inc.
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

import com.sun.xml.bind.v2.TODO;
import hudson.ExtensionList;
import hudson.diagnosis.OldDataMonitor;
import hudson.model.queue.Tasks;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.security.plugins.ldap.LDAPConfiguration;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlSelect;
import org.junit.Assume;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import org.jvnet.hudson.test.RealJenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import java.util.Map;
import java.util.logging.Level;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

public class LDAPEmbeddedFIPSTest {
    @ClassRule
    public static final LoggerRule log = new LoggerRule();
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @ClassRule
    public static FlagRule<String> fipsSystemPropertyRule =
            FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");

    @Rule
    public RealJenkinsRule r = new RealJenkinsRule().javaOptions("-Djenkins.security.FIPS140.COMPLIANCE=true")
            .withDebugPort(5008)
            .withDebugServer(true)
            .withDebugSuspend(true);

    @Test
    @LocalData
    public void testBlowsUpOnStart() throws Throwable {
        r.then(LDAPEmbeddedFIPSTest::verifyOldData);
    }

    static void verifyOldData(JenkinsRule j) throws Throwable {
        OldDataMonitor monitor = ExtensionList.lookupSingleton(OldDataMonitor.class);
        LDAPConfiguration.LDAPConfigurationDescriptor descriptor = Jenkins.get().getDescriptorByType(LDAPConfiguration.LDAPConfigurationDescriptor.class);
        assertNotNull(descriptor);
//        Map map =  monitor.getData();
//        OldDataMonitor.VersionRange versionRange = monitor.getData().get(descriptor);
//        assertNotNull(versionRange);
//        assertThat(versionRange.extra, containsString("LDAP server URL is not secure:" ));
        assertThat("FIPS message is logged", log, LoggerRule.recorded(Level.SEVERE, containsString("LDAP server URL is not secure:")));
    }

    @Test
    public void testPasswordCheck() {
        //Test when password is null
        LDAPConfiguration configuration = new LDAPConfiguration("ldaps://ldap.example.com", "dc=example,dc=com", true, null, null);
        assertNotNull(configuration);

        // Test with a short password
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Password is too short");
        configuration = new LDAPConfiguration("ldaps://ldap.example.com", "dc=example,dc=com", true, null, Secret.fromString("shortString"));

        //Test with a strong password
        configuration = new LDAPConfiguration("ldaps://ldap.example.com", "dc=example,dc=com", true, null, Secret.fromString("ThisIsVeryStrongPassword"));
        assertNotNull(configuration);
    }

    @Test
    public void testConfig() throws Throwable {
        r.then(LDAPEmbeddedFIPSTest::_testConfig);
    }

    public static void _testConfig(JenkinsRule j) throws Exception {

        // Create and set the LDAP Security Realm configuration
        LDAPSecurityRealm ldapRealm = new LDAPSecurityRealm(
                "ldap://ldap.example.com",              // LDAP Server URL
                "dc=example,dc=com",                    // Root DN
                "ou=users,dc=example,dc=com",           // User search base
                "uid={0}",                               // User search filter
                null,                                    // Group search base (optional)
                null,                                    // Group search filter (optional)
                null,                                    // Manager DN (optional)
                false                                     // Manager password (optional)
        );
        j.jenkins.setSecurityRealm(ldapRealm);

        // Set the LDAP security realm in Jenkins

        //Jenkins.getInstance().save();
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            // Navigate to "Manage Jenkins"
            HtmlPage manageJenkinsPage = wc.goTo("manage");

            // Navigate to "Configure Global Security"
            HtmlPage securityPage = wc.goTo("configureSecurity");

            // Find the form for global security configuration
            HtmlForm securityForm = securityPage.getFormByName("config");

            securityForm.getFormElements().forEach(element -> {
                System.out.println("Element Name: " + element.getId());
            });

            // Loop through all form elements and print their names
            securityForm.getInputsByName("").forEach(input -> {
                System.out.println("Input Name: " + input.getNameAttribute());
            });

           /* // If you need to include other form elements (like selects, text areas, etc.):
            securityForm.getAllElements().forEach(element -> {
                if (element.getAttribute("name") != null) {
                    System.out.println("Element Name: " + element.getAttribute("name"));
                }
            });
            System.out.println("Old Value ==> "+ securityRealmSelect.getSelectedIndex());
            // Select the LDAP option
            securityRealmSelect.setSelectedAttribute("LDAP", true);

            System.out.println("New Value ==> "+ securityRealmSelect.getSelectedIndex());*/

        }
    }
}
