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

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import hudson.model.User;
import hudson.tasks.MailAddressResolver;
import hudson.tasks.Mailer;
import hudson.util.FormValidation;
import hudson.util.Secret;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.stream.Collectors;

import jenkins.model.IdStrategy;
import jenkins.security.SecurityListener;
import jenkins.security.plugins.ldap.*;
import edu.umd.cs.findbugs.annotations.NonNull;
import org.jvnet.hudson.test.Issue;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

@LDAPTestConfiguration
public class LDAPEmbeddedTest {
    public LDAPRule ads = new LDAPRule();
    public JenkinsRule r = new JenkinsRule();
    @Rule
    public RuleChain chain = RuleChain.outerRule(ads).around(r);
    @Rule
    public LoggerRule log = new LoggerRule();

    @Test
    @LDAPSchema(ldif = "sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    public void userLookup_rolesFromGroupSearch() throws Exception {
        LDAPSecurityRealm realm = new LDAPSecurityRealm(
                ads.getUrl(),
                null,
                null,
                null,
                null,
                null,
                new FromGroupSearchLDAPGroupMembershipStrategy(null),
                "uid=admin,ou=system",
                Secret.fromString("pass"),
                false,
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                new LDAPSecurityRealm.EnvironmentProperty[0],
                "cn",
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        r.jenkins.setSecurityRealm(realm);
        User user = User.get("hhornblo", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS Lydia", "ROLE_HMS LYDIA"));
        assertThat(user.getDisplayName(), is("Horatio Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        UserDetails details = realm.authenticate2("hhornblo", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS Lydia", "ROLE_HMS LYDIA"));
        user = User.get("hnelson", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS Victory", "ROLE_HMS VICTORY"));
        assertThat(user.getDisplayName(), is("Horatio Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));
        details = realm.authenticate2("hnelson", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS Victory", "ROLE_HMS VICTORY"));
    }

    @Test
    @LDAPSchema(ldif = "sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    public void userLookup_rolesFromUserRecord() throws Exception {
        LDAPSecurityRealm realm = new LDAPSecurityRealm(
                ads.getUrl(),
                null,
                null,
                null,
                null,
                null,
                new FromUserRecordLDAPGroupMembershipStrategy("memberOf"),
                "uid=admin,ou=system",
                Secret.fromString("pass"),
                false,
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                new LDAPSecurityRealm.EnvironmentProperty[0],
                "cn",
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        r.jenkins.setSecurityRealm(realm);
        User user = User.get("hhornblo", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS_Lydia", "ROLE_HMS_LYDIA"));
        assertThat(user.getDisplayName(), is("Horatio Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        UserDetails details = realm.authenticate2("hhornblo", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS_Lydia", "ROLE_HMS_LYDIA"));
        user = User.get("hnelson", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS_Victory", "ROLE_HMS_VICTORY"));
        assertThat(user.getDisplayName(), is("Horatio Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));
        details = realm.authenticate2("hnelson", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS_Victory", "ROLE_HMS_VICTORY"));
    }

    @Test
    @LDAPSchema(ldif = "sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    public void userLookup_rolesFromGroupSearch_modern() throws Exception {
        LDAPSecurityRealm realm = new LDAPSecurityRealm(
                ads.getUrl(),
                null,
                null,
                null,
                null,
                null,
                new FromGroupSearchLDAPGroupMembershipStrategy(null),
                "uid=admin,ou=system",
                Secret.fromString("pass"),
                false,
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                new LDAPSecurityRealm.EnvironmentProperty[0],
                "cn",
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        realm.setDisableRolePrefixing(true);
        r.jenkins.setSecurityRealm(realm);
        User user = User.get("hhornblo", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS Lydia"));
        assertThat(user.getDisplayName(), is("Horatio Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        UserDetails details = realm.authenticate2("hhornblo", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS Lydia"));
        user = User.get("hnelson", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS Victory"));
        assertThat(user.getDisplayName(), is("Horatio Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));
        details = realm.authenticate2("hnelson", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS Victory"));
    }

    @Test
    @LDAPSchema(ldif = "sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    public void userLookup_rolesFromUserRecord_modern() throws Exception {
        LDAPSecurityRealm realm = new LDAPSecurityRealm(
                ads.getUrl(),
                null,
                null,
                null,
                null,
                null,
                new FromUserRecordLDAPGroupMembershipStrategy("memberOf"),
                "uid=admin,ou=system",
                Secret.fromString("pass"),
                false,
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                new LDAPSecurityRealm.EnvironmentProperty[0],
                "cn",
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        realm.setDisableRolePrefixing(true);
        r.jenkins.setSecurityRealm(realm);
        User user = User.get("hhornblo", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS_Lydia"));
        assertThat(user.getDisplayName(), is("Horatio Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        UserDetails details = realm.authenticate2("hhornblo", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS_Lydia"));
        user = User.get("hnelson", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS_Victory"));
        assertThat(user.getDisplayName(), is("Horatio Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));
        details = realm.authenticate2("hnelson", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS_Victory"));
    }

    private Set<String> userGetAuthorities(UserDetails details) {
        Set<String> authorities = new LinkedHashSet<>();
        for (GrantedAuthority a : details.getAuthorities()) {
            if (!a.equals(SecurityRealm.AUTHENTICATED_AUTHORITY2)) { // see User.getAuthorities()
                authorities.add(a.getAuthority());
            }
        }
        return authorities;
    }

    @Test
    @LDAPSchema(ldif = "sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    public void groupLookup() throws Exception {
        r.jenkins.setSecurityRealm(new LDAPSecurityRealm(
                ads.getUrl(),
                null,
                null,
                null,
                null,
                null,
                new FromGroupSearchLDAPGroupMembershipStrategy(null),
                "uid=admin,ou=system",
                Secret.fromString("pass"),
                false,
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                new LDAPSecurityRealm.EnvironmentProperty[0],
                "cn",
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE)
        );
        GroupDetails groupDetails = r.jenkins.getSecurityRealm().loadGroupByGroupname2("HMS Bounty", false);
        assertThat(groupDetails.getDisplayName(), is("HMS Bounty"));
        assertThat(groupDetails.getName(), is("HMS Bounty"));
        assertThat("LDAP security realm does not fetch group members by default", groupDetails.getMembers(), nullValue());
    }

    @Test
    @LDAPSchema(ldif = "sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    public void groupLookup_membersFromGroupSearch() throws Exception {
        r.jenkins.setSecurityRealm(new LDAPSecurityRealm(
                ads.getUrl(),
                null,
                null,
                null,
                null,
                null,
                new FromGroupSearchLDAPGroupMembershipStrategy(null),
                "uid=admin,ou=system",
                Secret.fromString("pass"),
                false,
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                new LDAPSecurityRealm.EnvironmentProperty[0],
                "cn",
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE)
        );
        GroupDetails groupDetails = r.jenkins.getSecurityRealm().loadGroupByGroupname2("HMS Bounty", true);
        assertThat(groupDetails.getDisplayName(), is("HMS Bounty"));
        assertThat(groupDetails.getName(), is("HMS Bounty"));
        assertThat(groupDetails.getMembers(), containsInAnyOrder("William Bligh", "Fletcher Christian", "John Fryer", "John Hallett"));
    }

    @Test
    @LDAPSchema(ldif = "sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    public void groupLookup_membersFromUserRecord() throws Exception {
        r.jenkins.setSecurityRealm(new LDAPSecurityRealm(
                ads.getUrl(),
                null,
                null,
                null,
                null,
                "(& (cn={0}) (objectclass=simulatedMicrosoftSecurityGroup))",
                new FromUserRecordLDAPGroupMembershipStrategy("memberOf"),
                "uid=admin,ou=system",
                Secret.fromString("pass"),
                false,
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                new LDAPSecurityRealm.EnvironmentProperty[0],
                "cn",
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE)
        );
        GroupDetails groupDetails = r.jenkins.getSecurityRealm().loadGroupByGroupname2("HMS_Bounty", true);
        assertThat(groupDetails.getDisplayName(), is("HMS_Bounty"));
        assertThat(groupDetails.getName(), is("HMS_Bounty"));
        assertThat(groupDetails.getMembers(), containsInAnyOrder("William Bligh", "Fletcher Christian", "John Fryer", "John Hallett"));
    }

    @Test
    @LDAPSchema(ldif = "planetexpress", id = "planetexpress", dn = "dc=planetexpress,dc=com")
    public void login() throws Exception {
        LDAPSecurityRealm realm =
                new LDAPSecurityRealm(ads.getUrl(), "dc=planetexpress,dc=com", null, null, null, null, null,
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

    @Test
    @LDAPSchema(ldif = "planetexpress", id = "planetexpress", dn = "dc=planetexpress,dc=com")
    public void login2() throws Exception {
        LDAPSecurityRealm realm =
                new LDAPSecurityRealm(ads.getUrl(), "dc=com", "dc=planetexpress", null, "dc=planetexpress", null, null,
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

    @Test
    @LDAPSchema(ldif = "planetexpress", id = "planetexpress", dn = "dc=planetexpress,dc=com")
    public void login3() throws Exception {
        LDAPSecurityRealm realm =
                new LDAPSecurityRealm(ads.getUrl(), "", "dc=planetexpress,dc=com", null, "dc=planetexpress,dc=com", null, null,
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
    
    @Test
    @LDAPSchema(ldif = "planetexpress", id = "planetexpress", dn = "dc=planetexpress,dc=com")
    @Issue("JENKINS-67664")
    public void fireAuthenticated() throws Exception {
        LDAPSecurityRealm realm =
            new LDAPSecurityRealm(ads.getUrl(), "dc=planetexpress,dc=com", null, null, null, null, null,
                "uid=admin,ou=system", Secret.fromString("pass"), false, false, null,
                null, "cn", "mail", null, null);
        r.jenkins.setSecurityRealm(realm);
        r.configRoundtrip();

        final AtomicBoolean authenticatedFired = new AtomicBoolean(false);
        r.jenkins.getExtensionList(SecurityListener.class).add(0, new SecurityListener() {
            @Override
            protected void authenticated2(@NonNull UserDetails details) {
                assertThat(details, instanceOf(LdapUserDetails.class));
                assertThat(details.getUsername(), is("fry"));
                assertThat(details.getAuthorities().size(), is(5));
                assertThat(details.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()), 
                    containsInAnyOrder("ROLE_CREW","authenticated","staff","crew","ROLE_STAFF"));
                assertThat(((LdapUserDetails)details).getDn(), is("cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com"));
                authenticatedFired.set(true);
            }
        });
        String content = r.createWebClient().login("fry", "fry").goTo("whoAmI").getBody().getTextContent();
        assertThat(content, containsString("Philip J. Fry"));
        assertThat(authenticatedFired.get(), is(true));
    }

    @Test
    @LDAPSchema(ldif = "planetexpress", id = "planetexpress", dn = "dc=planetexpress,dc=com")
    @Issue("JENKINS-2131")
    public void fireFailedToAuthenticate() throws Exception {
        log.record(SecurityListener.class, Level.FINE).capture(20);
        LDAPSecurityRealm realm =
            new LDAPSecurityRealm(ads.getUrl(), "dc=planetexpress,dc=com", null, null, null, null, null,
                "uid=admin,ou=system", Secret.fromString("pass"), false, false, null,
                null, "cn", "mail", null, null);
        r.jenkins.setSecurityRealm(realm);
        r.configRoundtrip();

        final AtomicBoolean failedToAuthFired = new AtomicBoolean(false);
        r.jenkins.getExtensionList(SecurityListener.class).add(0, new SecurityListener() {
                @Override
                protected void failedToAuthenticate(@NonNull String username) {
                        assertThat(username, is("fry"));
                        failedToAuthFired.set(true);
                }
        });

        try {
            r.createWebClient().login("fry", "imposter");
            fail("Should not be able to login");
        } catch (FailingHttpStatusCodeException e) {
            System.out.println("Got a bad login==good");
        }

        assertThat(log, LoggerRule.recorded(Level.FINE, containsString("failed to authenticate")));
        assertThat(failedToAuthFired.get(), is(true));
    }

    @Test
    @LDAPSchema(ldif = "sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    public void validate() throws Exception {
        LDAPSecurityRealm realm = new LDAPSecurityRealm(
                ads.getUrl(),
                null,
                null,
                null,
                null,
                null,
                new FromGroupSearchLDAPGroupMembershipStrategy(null),
                "uid=admin,ou=system",
                Secret.fromString("pass"),
                false,
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                new LDAPSecurityRealm.EnvironmentProperty[0],
                "cn",
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        realm.setDisableRolePrefixing(true);
        FormValidation validation = realm.getDescriptor().validate(realm, "hnelson", "pass");

        assertThat("Group details reported", validation.renderHtml(),
                allOf(
                        containsString("HMS Victory"),
                        not(containsString("HMS_Victory"))
                )
        );
        assertThat("Validation positive", validation.renderHtml(),
                allOf(
                        containsString("'validation-ok'"),
                        not(containsString("'warning'")),
                        not(containsString("'error'"))
                )
        );
        Document validationDoc = Jsoup.parse(validation.renderHtml());
        assertThat(validationDoc.select("[data-test='authentication']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='authentication-username']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='authentication-dn']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='authentication-displayname']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='authentication-email']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='authentication-groups']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='lookup']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='lookup-username']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='lookup-dn']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='lookup-displayname']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='lookup-email']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='lookup-groups']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='consistency']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='resolve-groups']").attr("class"),
                containsString("validation-ok"));
        assertThat(validation.kind, is(FormValidation.Kind.OK));
        validation = realm.getDescriptor().validate(realm, "hnelson", "badpass");

        assertThat("Group details reported", validation.renderHtml(),
                allOf(
                        containsString("HMS Victory"),
                        not(containsString("HMS_Victory"))
                )
        );
        assertThat("Validation negative", validation.renderHtml(),
                allOf(
                        containsString("'validation-ok'"),
                        not(containsString("'warning'")),
                        containsString("'error'")
                )
        );
        validationDoc = Jsoup.parse(validation.renderHtml());
        assertThat(validationDoc.select("[data-test='authentication']").attr("class"),
                containsString("error"));
        assertThat(validationDoc.select("[data-test='authentication-username']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='authentication-dn']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='authentication-displayname']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='authentication-email']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='authentication-groups']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='lookup']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='lookup-username']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='lookup-dn']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='lookup-displayname']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='lookup-email']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='lookup-groups']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='consistency']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='resolve-groups']").attr("class"),
                containsString("validation-ok"));
        assertThat("Always report outer kind as OK", validation.kind, is(FormValidation.Kind.OK));
        realm = new LDAPSecurityRealm(
                ads.getUrl(),
                null,
                null,
                null,
                null,
                null,
                new FromGroupSearchLDAPGroupMembershipStrategy(null),
                "uid=admin,ou=system",
                Secret.fromString("pass"),
                false,
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                new LDAPSecurityRealm.EnvironmentProperty[0],
                "bar",
                "foo",
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        realm.setDisableRolePrefixing(true);
        validation = realm.getDescriptor().validate(realm, "hnelson", "pass");
        assertThat("Group details reported", validation.renderHtml(),
                allOf(
                        containsString("HMS Victory"),
                        not(containsString("HMS_Victory"))
                )
        );
        assertThat("Validation warning", validation.renderHtml(),
                allOf(
                        containsString("'validation-ok'"),
                        containsString("'warning'"),
                        not(containsString("'error'"))
                )
        );
        validationDoc = Jsoup.parse(validation.renderHtml());
        assertThat(validationDoc.select("[data-test='authentication']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='authentication-username']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='authentication-dn']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='authentication-displayname']").attr("class"),
                containsString("warning"));
        assertThat(validationDoc.select("[data-test='authentication-displayname']").select("li").text(),
                allOf(containsString("cn"), containsString("memberof"), containsString("description")));
        assertThat(validationDoc.select("[data-test='authentication-email']").attr("class"),
                containsString("warning"));
        assertThat(validationDoc.select("[data-test='authentication-email']").select("li").text(),
                allOf(containsString("cn"), containsString("memberof"), containsString("description")));
        assertThat(validationDoc.select("[data-test='authentication-groups']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='lookup']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='lookup-username']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='lookup-dn']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='lookup-displayname']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='lookup-email']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='lookup-groups']").attr("class"),
                is(""));
        assertThat(validationDoc.select("[data-test='consistency']").attr("class"),
                containsString("validation-ok"));
        assertThat(validationDoc.select("[data-test='resolve-groups']").attr("class"),
                containsString("validation-ok"));
        assertThat("Always report outer kind as OK", validation.kind, is(FormValidation.Kind.OK));
    }

    @Test
    @Issue("JENKINS-68748")
    @LDAPSchema(ldif = "sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    public void validateUI() throws Exception {
        LDAPSecurityRealm realm = new LDAPSecurityRealm(
            ads.getUrl(),
            null,
            null,
            null,
            null,
            null,
            new FromGroupSearchLDAPGroupMembershipStrategy(null),
            "uid=admin,ou=system",
            Secret.fromString("pass"),
            false,
            false,
            new LDAPSecurityRealm.CacheConfiguration(100, 1000),
            new LDAPSecurityRealm.EnvironmentProperty[0],
            "cn",
            null,
            IdStrategy.CASE_INSENSITIVE,
            IdStrategy.CASE_INSENSITIVE);
        realm.setDisableRolePrefixing(true);
        r.jenkins.setSecurityRealm(realm);
        r.jenkins.getSecurityRealm().createSecurityComponents();

        try(JenkinsRule.WebClient c = r.createWebClient().withJavaScriptEnabled(true)) {
            
            final HtmlPage security = c.goTo("configureSecurity");
            final HtmlForm form = security.getFormByName("config");

            HtmlButton testButton = form.getButtonByName("validateLdapSettings");
            assertThat(testButton, notNullValue());
            testButton.click();

            c.waitForBackgroundJavaScript(2000);

            final HtmlInput testUser = security.getElementByName("testUser");
            testUser.setAttribute("value", "hnelson");
            final HtmlInput testPassword = security.getElementByName("testPassword");
            testPassword.setAttribute("value", "pass");

            HtmlButton submitElement = null;
            for (DomElement e : security.getElementsByTagName("button")) {
                if ("submit".equals(e.getAttribute("type")) && "Test".equals(e.getTextContent())) {
                    submitElement = (HtmlButton) e;
                    break;
                }
            }

            assertThat(submitElement, notNullValue());
            submitElement.click();

            c.waitForBackgroundJavaScript(2000);

            Document validationDoc = Jsoup.parse(security.asXml());
            assertThat(validationDoc.select("[data-test='authentication']").attr("class"),
                containsString("validation-ok"));
            assertThat(validationDoc.select("[data-test='authentication-username']").attr("class"),
                containsString("validation-ok"));
            assertThat(validationDoc.select("[data-test='authentication-dn']").attr("class"),
                containsString("validation-ok"));
            assertThat(validationDoc.select("[data-test='authentication-displayname']").attr("class"),
                containsString("validation-ok"));
            assertThat(validationDoc.select("[data-test='authentication-email']").attr("class"),
                containsString("validation-ok"));
            assertThat(validationDoc.select("[data-test='authentication-groups']").attr("class"),
                containsString("validation-ok"));
            assertThat(validationDoc.select("[data-test='lookup']").attr("class"),
                containsString("validation-ok"));
            assertThat(validationDoc.select("[data-test='lookup-username']").attr("class"),
                is(""));
            assertThat(validationDoc.select("[data-test='lookup-dn']").attr("class"),
                is(""));
            assertThat(validationDoc.select("[data-test='lookup-displayname']").attr("class"),
                is(""));
            assertThat(validationDoc.select("[data-test='lookup-email']").attr("class"),
                is(""));
            assertThat(validationDoc.select("[data-test='lookup-groups']").attr("class"),
                is(""));
            assertThat(validationDoc.select("[data-test='consistency']").attr("class"),
                containsString("validation-ok"));
            assertThat(validationDoc.select("[data-test='resolve-groups']").attr("class"),
                containsString("validation-ok"));
        }
    }

    @Test
    @LDAPSchema(ldif = "planetexpress", id = "planetexpress", dn = "dc=planetexpress,dc=com")
    public void usingEnvironmentProperties() throws Exception {
        log.record(LDAPSecurityRealm.class, Level.WARNING).capture(10);
        LDAPConfiguration c = new LDAPConfiguration(ads.getUrl(), "", false, "uid=admin,ou=system", Secret.fromString("pass"));

        LDAPSecurityRealm.EnvironmentProperty[] environmentProperties = {new LDAPSecurityRealm.EnvironmentProperty("java.naming.security.protocol", "ssl")};
        c.setEnvironmentProperties(environmentProperties);

        List<LDAPConfiguration> configurations = new ArrayList<>();
        configurations.add(c);
        LDAPSecurityRealm realm = new LDAPSecurityRealm(
            configurations,
            false,
            new LDAPSecurityRealm.CacheConfiguration(100, 1000),
            IdStrategy.CASE_INSENSITIVE,
            IdStrategy.CASE_INSENSITIVE
        );

        r.jenkins.setSecurityRealm(realm);
        r.submit(r.createWebClient().goTo("configureSecurity").getFormByName("config"));

        try {
            r.createWebClient().login("fry", "fry");
            fail("Should not be able to login");
        } catch (FailingHttpStatusCodeException e) {
            System.out.println("Got a bad login==good");
        }
        assertThat(log, LoggerRule.recorded(Level.WARNING, containsString("Failed communication with ldap server")));
    }

    @Test
    @LDAPSchema(ldif = "planetexpressExtGroups_withCn", id = "planetexpress", dn = "dc=planetexpress,dc=com")
    public void extGroupWithOneCN() throws Exception {
        LDAPConfiguration ldapConfiguration = new LDAPConfiguration(ads.getUrl(), "", false, "uid=admin,ou=system", Secret.fromString("pass"));
        LDAPSecurityRealm realm =
              new LDAPSecurityRealm(Collections.singletonList(ldapConfiguration),false, null, null, null);
        r.jenkins.setSecurityRealm(realm);
        r.configRoundtrip();
        assertThat(r.jenkins.getSecurityRealm().loadGroupByGroupname2("cn_example3", false).getDisplayName(), is("cn_example3"));
    }

    @Test
    @LDAPSchema(ldif = "planetexpressExtGroups_withCn", id = "planetexpress", dn = "dc=planetexpress,dc=com")
    public void extGroupWithMultipleCN() throws Exception {
        log.record(LDAPSecurityRealm.class, Level.ALL).capture(10);
        LDAPConfiguration ldapConfiguration = new LDAPConfiguration(ads.getUrl(), "", false, "uid=admin,ou=system", Secret.fromString("pass"));
        LDAPSecurityRealm realm =
              new LDAPSecurityRealm(Collections.singletonList(ldapConfiguration),false, null, null, null);
        r.jenkins.setSecurityRealm(realm);
        r.configRoundtrip();
        assertThat(r.jenkins.getSecurityRealm().loadGroupByGroupname2("cn_example1", false).getDisplayName(), is("cn_example1"));
        assertThat(log.getMessages(), hasItem(endsWith("The first one  (cn_example1) has been assigned as external group name")));
    }

    @Test
    @Issue("JENKINS-55813")
    @LDAPSchema(ldif = "planetexpressWithPPolicy", id = "planetexpress", dn = "dc=planetexpress,dc=com")
    public void userValidityAttributes() throws Exception {
        LDAPConfiguration configuration = new LDAPConfiguration(ads.getUrl(), "dc=planetexpress,dc=com", false, "uid=admin,ou=system", Secret.fromString("pass"));
        LDAPSecurityRealm realm = new LDAPSecurityRealm(Collections.singletonList(configuration), false, null, null, null);
        r.jenkins.setSecurityRealm(realm);
        r.configRoundtrip();
        assertThrows(DisabledException.class, () -> realm.loadUserByUsername2("amy"));
        assertThrows(DisabledException.class, () -> User.getById("amy", true).impersonate2());
        assertThrows(AccountExpiredException.class, () -> realm.loadUserByUsername2("bender"));
        assertThrows(AccountExpiredException.class, () -> User.getById("bender", true).impersonate2());
        assertThrows(FailingHttpStatusCodeException.class, () -> r.createWebClient().withBasicApiToken("amy").goTo(""));
    }
}
