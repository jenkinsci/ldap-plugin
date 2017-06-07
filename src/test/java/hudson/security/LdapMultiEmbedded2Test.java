package hudson.security;

import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.util.Secret;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.FromGroupSearchLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.FromUserRecordLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.LDAPConfiguration;
import jenkins.security.plugins.ldap.LDAPRule;
import jenkins.security.plugins.ldap.LDAPTestConfiguration;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.ArrayList;
import java.util.Arrays;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

/**
 * Tests connecting to two different embedded servers using slightly different configurations.
 */
@LDAPTestConfiguration
public class LdapMultiEmbedded2Test {
    public LDAPRule sevenSeas = new LDAPRule();
    public LDAPRule planetExpress = new LDAPRule();
    public JenkinsRule r = new JenkinsRule();
    @Rule
    public RuleChain chain = RuleChain.outerRule(sevenSeas).around(planetExpress).around(r);

    @Before
    public void setup() throws Exception {
        sevenSeas.loadSchema("sevenSeas", "o=sevenSeas", getClass().getResourceAsStream("/hudson/security/sevenSeas.ldif"));
        planetExpress.loadSchema("planetexpress", "dc=planetexpress,dc=com", getClass().getResourceAsStream("/hudson/security/planetexpressWithHNelson.ldif"));

        LDAPConfiguration sevenSeasConf = new LDAPConfiguration(
                sevenSeas.getUrl(),
                null,
                false,
                "uid=admin,ou=system",
                Secret.fromString("pass"));
        sevenSeasConf.setUserSearchBase("ou=people,o=sevenSeas");
        sevenSeasConf.setUserSearch("sAMAccountName={0}");
        sevenSeasConf.setGroupSearchBase("ou=groups,o=sevenSeas");
        sevenSeasConf.setGroupSearchFilter(null);
        sevenSeasConf.setGroupMembershipStrategy(new FromUserRecordLDAPGroupMembershipStrategy("memberof"));
        sevenSeasConf.setDisplayNameAttributeName("sn"); //Different than the next so we can see that difference is made
        sevenSeasConf.setMailAddressAttributeName(null);

        LDAPConfiguration planetExpressConf = new LDAPConfiguration(planetExpress.getUrl(), "dc=planetexpress,dc=com", false, "uid=admin,ou=system", Secret.fromString("pass"));
        planetExpressConf.setUserSearchBase("ou=people");
        planetExpressConf.setUserSearch(null);
        planetExpressConf.setGroupSearchBase("ou=groups");
        planetExpressConf.setGroupSearchFilter(null);
        planetExpressConf.setGroupMembershipStrategy(new FromGroupSearchLDAPGroupMembershipStrategy("uniquemember={0}"));
        planetExpressConf.setDisplayNameAttributeName("cn"); //Different than the first so we can see that difference is made
        planetExpressConf.setMailAddressAttributeName("mail");


        r.jenkins.setSecurityRealm(new LDAPSecurityRealm(
                Arrays.asList(sevenSeasConf, planetExpressConf),
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE)
        );
    }

    @Test
    public void lookUp() {
        //First server
        User user = User.get("hnelson");
        assertThat(user.getAuthorities(), allOf(hasItem("HMS_Victory"), hasItem("ROLE_HMS_VICTORY")));
        assertThat(user.getDisplayName(), is("Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));

        UserDetails details = r.jenkins.getSecurityRealm().getSecurityComponents().userDetails.loadUserByUsername("hnelson");
        assertThat(details, instanceOf(LDAPSecurityRealm.DelegatedLdapUserDetails.class));
        assertEquals(sevenSeas.getUrl(), ((LDAPSecurityRealm.DelegatedLdapUserDetails)details).getServer());

        //Second server
        user = User.get("fry");
        assertThat(user.getAuthorities(), allOf(hasItem("crew"), hasItem("staff")));
        assertThat(user.getDisplayName(), is("Philip J. Fry"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("fry@planetexpress.com"));
        details = r.jenkins.getSecurityRealm().getSecurityComponents().userDetails.loadUserByUsername("fry");
        assertThat(details, instanceOf(LDAPSecurityRealm.DelegatedLdapUserDetails.class));
        assertEquals(planetExpress.getUrl(), ((LDAPSecurityRealm.DelegatedLdapUserDetails)details).getServer());
    }

    @Test
    public void login() throws Exception {
        final AuthenticationManager manager = r.jenkins.getSecurityRealm().getSecurityComponents().manager;
        //First Server
        Authentication auth = manager.authenticate(new UsernamePasswordAuthenticationToken("hnelson", "pass"));
        assertNotNull(auth);
        assertThat(auth, instanceOf(LDAPSecurityRealm.DelegatedLdapAuthentication.class));
        assertEquals(sevenSeas.getUrl(), ((LDAPSecurityRealm.DelegatedLdapAuthentication)auth).getServer());

        //Second Server
        auth = manager.authenticate(new UsernamePasswordAuthenticationToken("fry", "fry"));
        assertNotNull(auth);
        assertThat(auth, instanceOf(LDAPSecurityRealm.DelegatedLdapAuthentication.class));
        assertEquals(planetExpress.getUrl(), ((LDAPSecurityRealm.DelegatedLdapAuthentication)auth).getServer());

        //Exists on both servers with different passwords, trying passwd from server 2 should fail
        try {
            //Verified to work before the fix but shouldn't any longer
            manager.authenticate(new UsernamePasswordAuthenticationToken("hnelson", "hnelson"));
            fail("Should not be able to login with same username on server two");
        } catch (BadCredentialsException e) {
            System.out.println("Got a bad login==good");
        }
    }
}
