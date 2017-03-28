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

import hudson.model.User;
import hudson.tasks.MailAddressResolver;
import hudson.tasks.Mailer;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.util.LinkedHashSet;
import java.util.Set;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.FromGroupSearchLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.FromUserRecordLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.LDAPConfiguration;
import jenkins.security.plugins.ldap.LDAPRule;
import jenkins.security.plugins.ldap.LDAPSchema;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
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

@LDAPConfiguration
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
        assertThat(validation.kind, is(FormValidation.Kind.OK));
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
        assertThat(validation.kind, is(FormValidation.Kind.WARNING));
    }

}
