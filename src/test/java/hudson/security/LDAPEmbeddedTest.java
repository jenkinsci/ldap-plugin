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
import hudson.model.User;
import hudson.tasks.MailAddressResolver;
import hudson.tasks.Mailer;
import hudson.util.FormValidation;
import hudson.util.Secret;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.*;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule;

import static hudson.security.SecurityRealm.AUTHENTICATED_AUTHORITY;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@LDAPTestConfiguration
public class LDAPEmbeddedTest {
    public LDAPRule ads = new LDAPRule();
    public JenkinsRule r = new JenkinsRule();
    @Rule
    public RuleChain chain = RuleChain.outerRule(ads).around(r);

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
        User user = User.get("hhornblo");
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS Lydia", "ROLE_HMS LYDIA"));
        assertThat(user.getDisplayName(), is("Horatio Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        UserDetails details = realm.authenticate("hhornblo", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS Lydia", "ROLE_HMS LYDIA"));
        user = User.get("hnelson");
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS Victory", "ROLE_HMS VICTORY"));
        assertThat(user.getDisplayName(), is("Horatio Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));
        details = realm.authenticate("hnelson", "pass");
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
        User user = User.get("hhornblo");
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS_Lydia", "ROLE_HMS_LYDIA"));
        assertThat(user.getDisplayName(), is("Horatio Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        UserDetails details = realm.authenticate("hhornblo", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS_Lydia", "ROLE_HMS_LYDIA"));
        user = User.get("hnelson");
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS_Victory", "ROLE_HMS_VICTORY"));
        assertThat(user.getDisplayName(), is("Horatio Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));
        details = realm.authenticate("hnelson", "pass");
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
        User user = User.get("hhornblo");
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS Lydia"));
        assertThat(user.getDisplayName(), is("Horatio Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        UserDetails details = realm.authenticate("hhornblo", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS Lydia"));
        user = User.get("hnelson");
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS Victory"));
        assertThat(user.getDisplayName(), is("Horatio Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));
        details = realm.authenticate("hnelson", "pass");
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
        User user = User.get("hhornblo");
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS_Lydia"));
        assertThat(user.getDisplayName(), is("Horatio Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        UserDetails details = realm.authenticate("hhornblo", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS_Lydia"));
        user = User.get("hnelson");
        assertThat(user.getAuthorities(), containsInAnyOrder("HMS_Victory"));
        assertThat(user.getDisplayName(), is("Horatio Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));
        details = realm.authenticate("hnelson", "pass");
        assertThat(userGetAuthorities(details), containsInAnyOrder("HMS_Victory"));
    }

    private Set<String> userGetAuthorities(UserDetails details) {
        Set<String> authorities = new LinkedHashSet<>();
        for (GrantedAuthority a : details.getAuthorities()) {
            if (!a.equals(AUTHENTICATED_AUTHORITY)) { // see User.getAuthorities()
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
        GroupDetails groupDetails = r.jenkins.getSecurityRealm().loadGroupByGroupname("HMS Bounty");
        assertThat(groupDetails.getDisplayName(), is("HMS Bounty"));
        assertThat(groupDetails.getName(), is("HMS Bounty"));
        assertThat("LDAP security realm does not support group member query", groupDetails.getMembers(), nullValue());
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


        LdapUserDetails zoidberg = (LdapUserDetails) r.jenkins.getSecurityRealm().loadUserByUsername("zoidberg");
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


        LdapUserDetails zoidberg = (LdapUserDetails) r.jenkins.getSecurityRealm().loadUserByUsername("zoidberg");
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


        LdapUserDetails zoidberg = (LdapUserDetails) r.jenkins.getSecurityRealm().loadUserByUsername("zoidberg");
        assertThat(zoidberg.getDn(), is("cn=John A. Zoidberg,ou=people,dc=planetexpress,dc=com"));

        String leelaEmail = MailAddressResolver.resolve(r.jenkins.getUser("leela"));
        assertThat(leelaEmail, is("leela@planetexpress.com"));
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
    @LDAPSchema(ldif = "planetexpress", id = "planetexpress", dn = "dc=planetexpress,dc=com")
    public void usingEnvironmentProperties() throws Exception {
        LDAPConfiguration c = new LDAPConfiguration(ads.getUrl(), "", false, "uid=admin,ou=system", Secret.fromString("pass"));

        LDAPSecurityRealm.EnvironmentProperty[] environmentProperties = {new LDAPSecurityRealm.EnvironmentProperty("java.naming.ldap.typesOnly", "true")};
        c.setEnvironmentProperties(environmentProperties);

        List<LDAPConfiguration> configurations = new ArrayList<LDAPConfiguration>();
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
    }


}
