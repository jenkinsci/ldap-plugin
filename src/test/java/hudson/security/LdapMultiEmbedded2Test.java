package hudson.security;

import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.util.Secret;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.FromGroupSearchLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.FromUserRecordLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.LDAPConfiguration;
import jenkins.security.plugins.ldap.LDAPExtension;
import jenkins.security.plugins.ldap.LDAPTestConfiguration;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests connecting to two different embedded servers using slightly different configurations.
 */
@LDAPTestConfiguration
@WithJenkins
class LdapMultiEmbedded2Test {

    @RegisterExtension
    private final LDAPExtension sevenSeas = new LDAPExtension();
    @RegisterExtension
    private final LDAPExtension planetExpress = new LDAPExtension();
    private JenkinsRule r;

    private LDAPConfiguration sevenSeasConf;
    private LDAPConfiguration planetExpressConf;

    @BeforeEach
    void beforeEach(JenkinsRule rule) throws Exception {
        r = rule;
        sevenSeas.loadSchema("sevenSeas", "o=sevenSeas", getClass().getResourceAsStream("/hudson/security/sevenSeas.ldif"));
        planetExpress.loadSchema("planetexpress", "dc=planetexpress,dc=com", getClass().getResourceAsStream("/hudson/security/planetexpressWithHNelson.ldif"));

        sevenSeasConf = new LDAPConfiguration(
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

        planetExpressConf = new LDAPConfiguration(planetExpress.getUrl(), "dc=planetexpress,dc=com", false, "uid=admin,ou=system", Secret.fromString("pass"));
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
    void lookUp() {
        //First server
        User user = User.get("hnelson", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), allOf(hasItem("HMS_Victory"), hasItem("ROLE_HMS_VICTORY")));
        assertThat(user.getDisplayName(), is("Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));

        UserDetails details = r.jenkins.getSecurityRealm().getSecurityComponents().userDetails2.loadUserByUsername("hnelson");
        assertThat(details, instanceOf(LDAPSecurityRealm.DelegatedLdapUserDetails.class));
        assertEquals(sevenSeasConf.getId(), ((LDAPSecurityRealm.DelegatedLdapUserDetails)details).getConfigurationId());

        //Second server
        user = User.get("fry", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), allOf(hasItem("crew"), hasItem("staff")));
        assertThat(user.getDisplayName(), is("Philip J. Fry"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("fry@planetexpress.com"));
        details = r.jenkins.getSecurityRealm().getSecurityComponents().userDetails2.loadUserByUsername("fry");
        assertThat(details, instanceOf(LDAPSecurityRealm.DelegatedLdapUserDetails.class));
        assertEquals(planetExpressConf.getId(), ((LDAPSecurityRealm.DelegatedLdapUserDetails)details).getConfigurationId());
    }

    @Test
    void login() {
        final AuthenticationManager manager = r.jenkins.getSecurityRealm().getSecurityComponents().manager2;
        //First Server
        Authentication auth = manager.authenticate(new UsernamePasswordAuthenticationToken("hnelson", "pass"));
        assertNotNull(auth);
        assertThat(auth, instanceOf(LDAPSecurityRealm.DelegatedLdapAuthentication.class));
        assertEquals(sevenSeasConf.getId(), ((LDAPSecurityRealm.DelegatedLdapAuthentication)auth).getConfigurationId());

        //Second Server
        auth = manager.authenticate(new UsernamePasswordAuthenticationToken("fry", "fry"));
        assertNotNull(auth);
        assertThat(auth, instanceOf(LDAPSecurityRealm.DelegatedLdapAuthentication.class));
        assertEquals(planetExpressConf.getId(), ((LDAPSecurityRealm.DelegatedLdapAuthentication)auth).getConfigurationId());

        //Exists on both servers with different passwords, trying passwd from server 2 should fail

        //Verified to work before the fix but shouldn't any longer
        assertThrows(BadCredentialsException.class, () -> manager.authenticate(new UsernamePasswordAuthenticationToken("hnelson", "hnelson")),
                "Should not be able to login with same username on server two");
    }
}
