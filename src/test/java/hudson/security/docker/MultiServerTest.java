package hudson.security.docker;

import hudson.model.User;
import hudson.security.LDAPEmbeddedTest;
import hudson.security.LDAPSecurityRealm;
import hudson.tasks.MailAddressResolver;
import hudson.tasks.Mailer;
import hudson.util.Secret;
import java.util.Arrays;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.*;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.testcontainers.containers.GenericContainer;

/**
 * Tests connecting to two different servers
 */
@LDAPTestConfiguration
public class MultiServerTest {

    @BeforeClass public static void requiresDocker() {
        PlanetExpressTest.requiresDocker();
    }

    @SuppressWarnings("rawtypes")
    @Rule
    public GenericContainer container = new GenericContainer(PlanetExpressTest.TEST_IMAGE).withExposedPorts(389);

    public JenkinsRule j = new JenkinsRule();
    public LDAPRule ads = new LDAPRule();
    @Rule
    public RuleChain chain = RuleChain.outerRule(ads).around(j);

    /**
     * Same tests as {@link LDAPEmbeddedTest#userLookup()} and {@link PlanetExpressTest#login()} but both servers configured at the same time.
     *
     * @throws Exception if so
     */
    @Test
    @LDAPSchema(ldif = "/hudson/security/sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    public void userLookup() throws Exception {
        LDAPConfiguration adsConf = new LDAPConfiguration(
                ads.getUrl(),
                null,
                false,
                "uid=admin,ou=system",
                Secret.fromString("pass"));
        adsConf.setUserSearchBase(null);
        adsConf.setUserSearch(null);
        adsConf.setGroupSearchBase(null);
        adsConf.setGroupSearchFilter(null);
        adsConf.setGroupMembershipStrategy(new FromGroupSearchLDAPGroupMembershipStrategy(null));
        adsConf.setDisplayNameAttributeName("cn");
        adsConf.setMailAddressAttributeName(null);

        LDAPConfiguration plExprs = new LDAPConfiguration(
                container.getHost() + ":" + container.getFirstMappedPort(),
                PlanetExpressTest.DN,
                false,
                PlanetExpressTest.MANAGER_DN,
                Secret.fromString(PlanetExpressTest.MANAGER_SECRET));
        plExprs.setUserSearchBase(null);
        plExprs.setUserSearch(null);
        plExprs.setGroupSearchBase(null);
        plExprs.setGroupSearchFilter(null);
        plExprs.setGroupMembershipStrategy(new FromGroupSearchLDAPGroupMembershipStrategy(null));
        plExprs.setMailAddressAttributeName("mail");
        plExprs.setDisplayNameAttributeName("cn");

        LDAPSecurityRealm realm = new LDAPSecurityRealm(
                Arrays.asList(adsConf, plExprs),
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);

        j.jenkins.setSecurityRealm(realm);
        //j.configRoundtrip();

        //ads verification
        User user = User.get("hhornblo");
        assertThat(user.getAuthorities(), allOf(hasItem("HMS Lydia"), hasItem("ROLE_HMS LYDIA")));
        assertThat(user.getDisplayName(), is("Horatio Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        user = User.get("hnelson");
        assertThat(user.getAuthorities(), allOf(hasItem("HMS Victory"), hasItem("ROLE_HMS VICTORY")));
        assertThat(user.getDisplayName(), is("Horatio Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));

        //Planet Express verification
        String content = j.createWebClient().login("fry", "fry").goTo("whoAmI").getBody().getTextContent();
        assertThat(content, containsString("Philip J. Fry"));
        user = User.get("fry");
        assertThat(user.getDisplayName(), is("Philip J. Fry"));


        LdapUserDetails zoidberg = (LdapUserDetails) j.jenkins.getSecurityRealm().loadUserByUsername2("zoidberg");
        assertEquals("cn=John A. Zoidberg,ou=people,dc=planetexpress,dc=com", zoidberg.getDn());

        user = j.jenkins.getUser("leela");
        String leelaEmail = MailAddressResolver.resolve(user);
        assertEquals("leela@planetexpress.com", leelaEmail);
        assertThat(user.getDisplayName(), is("Turanga Leela"));

    }

}
