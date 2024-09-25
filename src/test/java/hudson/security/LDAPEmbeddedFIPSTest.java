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

import hudson.util.FormValidation;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import jenkins.model.Jenkins;
import hudson.tasks.MailAddressResolver;
import hudson.util.Secret;

import java.security.cert.X509Certificate;

import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.*;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.rules.ExpectedException;
import org.jvnet.hudson.test.FlagRule;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;

import javax.net.ssl.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;

@LDAPTestConfiguration(ldapsProtocol = true)
public class LDAPEmbeddedFIPSTest {
    public LDAPRule ads = new LDAPRule();
    public JenkinsRule r = new JenkinsRule();
    @Rule
    public RuleChain chain = RuleChain.outerRule(ads).around(r);
    @Rule
    public LoggerRule log = new LoggerRule();
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @ClassRule
    public static FlagRule<String> fipsSystemPropertyRule =
            FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");


    @BeforeClass
    public static void setUp(){
        disableSSLVerification();
    }

    //@Test
    @LDAPSchema(ldif = "planetexpress", id = "planetexpress", dn = "dc=planetexpress,dc=com")
    public void login() throws Exception {
       // disableSSLVerification();
        System.out.println(ads.getUrl());;
        String secureUrl = "ldaps://insecure.example.com";
        LDAPSecurityRealm realm =
                new LDAPSecurityRealm(ads.getUrlTls(), "dc=planetexpress,dc=com", null, null, null, null, null,
                        "uid=admin,ou=system", Secret.fromString("pass"), false, false, null,
                        null, "cn", "mail", null, null);
        r.jenkins.setSecurityRealm(realm);
        r.configRoundtrip();
        String content = r.createWebClient().login("fry", "fry").goTo("whoAmI").getBody().getTextContent();
        assertThat(content, containsString("Philip J. Fry"));


        LdapUserDetails zoidberg = (LdapUserDetails) r.jenkins.getSecurityRealm().loadUserByUsername2("zoidberg");
        assertThat(zoidberg.getDn(), is("cn=John A. Zoidberg,ou=people,dc=planetexpress,dc=com"));

        String leelaEmail = MailAddressResolver.resolve(r.jenkins.getUser("leela"));
        assertThat(leelaEmail, is("leela@planetexpress.com"));
    }

    public static void disableSSLVerification() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            };

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            HostnameVerifier allHostsValid = (hostname, session) -> true;
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
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
    public void testPasswordCheckOnCheckServer(){
        // Test with a short password
        FormValidation shortPasswordValidation = new LDAPConfiguration.LDAPConfigurationDescriptor().doCheckManagerPasswordSecret("short");
        assertEquals(FormValidation.Kind.ERROR, shortPasswordValidation.kind);
        assertThat(shortPasswordValidation.getMessage(), containsString("Password is too short"));

        // Test with a strong password but server validation fails hence checking for 'Unknown host'
        FormValidation strongPasswordValidation = new LDAPConfiguration.LDAPConfigurationDescriptor().doCheckManagerPasswordSecret("ThisIsVeryStrongPassword");
        assertEquals(FormValidation.Kind.OK, strongPasswordValidation.kind);
    }
}
