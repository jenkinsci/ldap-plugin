/*
 * The MIT License
 *
 * Copyright 2024 CloudBees,Inc.
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

import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.RealJenkinsExtension;
import org.jvnet.hudson.test.recipes.LocalData;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LDAPEmbeddedFIPSTest {

    private static final String LDAP_SERVER_ERROR_MESSAGE = "LDAP server URL is not secure";

    @RegisterExtension
    private final RealJenkinsExtension extension = new RealJenkinsExtension().javaOptions("-Djenkins.security.FIPS140.COMPLIANCE=true")
            .withDebugPort(5008);

    @Test
    @LocalData
    void testBlowsUpOnStart() throws Throwable {
        // Create a stream to hold the log messages
        ByteArrayOutputStream logStream = new ByteArrayOutputStream();
        System.setErr(new PrintStream(logStream));
        extension.startJenkins();
        String logs = logStream.toString();
        assertTrue(logs.contains(LDAP_SERVER_ERROR_MESSAGE));
    }

    @Test
    void testLdapServerUrl() throws Throwable {
        extension.then(LDAPEmbeddedFIPSTest::_testLdapServerUrl);
    }

    private static void _testLdapServerUrl(JenkinsRule j) throws Exception {
        // Create and set the LDAP Security Realm configuration
        LDAPSecurityRealm ldapRealm = new LDAPSecurityRealm(
                "ldaps://ldap.example.com",              // LDAP Server URL
                "dc=example,dc=com",                    // Root DN
                "ou=users,dc=example,dc=com",           // User search base
                "uid={0}",                               // User search filter
                null,                                    // Group search base (optional)
                null,                                    // Group search filter (optional)
                null,                                    // Manager DN (optional)
                false                                     // Manager password (optional)
        );
        // Set the LDAP security realm in Jenkins
        j.jenkins.setSecurityRealm(ldapRealm);
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            // Navigate to "Manage Jenkins"
            HtmlPage manageJenkinsPage = wc.goTo("manage");
            // Navigate to "Configure Global Security"
            HtmlPage securityPage = wc.goTo("configureSecurity");
            // Find the form for global security configuration
            HtmlForm securityForm = securityPage.getFormByName("config");
            securityForm.getInputByName("_.server").setValue("ldap.example.com");
            securityForm.getInputByName("_.server").blur();
            wc.waitForBackgroundJavaScript(1000);
            wc.setThrowExceptionOnFailingStatusCode(false);
            HtmlPage page = j.submit(securityForm);
            WebResponse webResponse = page.getWebResponse();
            assertNotEquals(200, webResponse.getStatusCode());
            assertThat(webResponse.getContentAsString(), containsString(LDAP_SERVER_ERROR_MESSAGE));
        }
    }

    @Test
    void testManagerPassword() throws Throwable {
        extension.then(LDAPEmbeddedFIPSTest::_testManagerPassword);
    }

    private static void _testManagerPassword(JenkinsRule j) throws Exception {
        // Create and set the LDAP Security Realm configuration
        LDAPSecurityRealm ldapRealm = new LDAPSecurityRealm(
                "ldaps://ldap.example.com",              // LDAP Server URL
                "dc=example,dc=com",                    // Root DN
                "ou=users,dc=example,dc=com",           // User search base
                "uid={0}",                               // User search filter
                null,                                    // Group search base (optional)
                null,                                    // Group search filter (optional)
                null,                                    // Manager DN (optional)
                false                                     // Manager password (optional)
        );
        // Set the LDAP security realm in Jenkins
        j.jenkins.setSecurityRealm(ldapRealm);
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            // Navigate to "Manage Jenkins"
            HtmlPage manageJenkinsPage = wc.goTo("manage");
            // Navigate to "Configure Global Security"
            HtmlPage securityPage = wc.goTo("configureSecurity");
            // Find the form for global security configuration
            HtmlForm securityForm = securityPage.getFormByName("config");
            wc.waitForBackgroundJavaScript(1000);
            securityForm.getInputByName("_.managerPasswordSecret").setValueAttribute("short");
            wc.setThrowExceptionOnFailingStatusCode(false);
            HtmlPage page = j.submit(securityForm);
            WebResponse webResponse = page.getWebResponse();
            assertNotEquals(200, webResponse.getStatusCode());
            assertThat(webResponse.getContentAsString(), containsString("Password is too short"));
        }
    }
}
