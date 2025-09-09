package hudson.security.docker;

import hudson.model.User;
import hudson.security.LDAPSecurityRealm;
import hudson.tasks.MailAddressResolver;
import hudson.tasks.Mailer;
import hudson.util.Secret;
import java.util.Arrays;
import java.util.Collections;

import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Tests connecting to two different servers
 */
@LDAPTestConfiguration
@Testcontainers(disabledWithoutDocker = true)
@WithJenkins
class MultiServerTest {

    private static final String TEST_IMAGE =
            "ghcr.io/rroemhild/docker-test-openldap:v2.5.0@sha256:3470e15c60119a1c0392cc162cdce71edfb42b55affdc69da574012f956317cd";
    private static final String DN = "dc=planetexpress,dc=com";
    private static final String MANAGER_DN = "cn=admin,dc=planetexpress,dc=com";
    private static final String MANAGER_SECRET = "GoodNewsEveryone";

    @SuppressWarnings("rawtypes")
    @Container
    private final GenericContainer container = new GenericContainer(TEST_IMAGE).withExposedPorts(10389);

    @RegisterExtension
    private final LDAPExtension ads = new LDAPExtension();

    private JenkinsRule r;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        r = rule;
    }

    /**
     * Same tests as {@link hudson.security.LDAPEmbeddedTest#userLookup()} and {@link PlanetExpressTest#login()} but both servers configured at the same time.
     *
     * @throws Exception if so
     */
    @Test
    @LDAPSchema(ldif = "/hudson/security/sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    void userLookup() throws Exception {
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
                DN,
                false,
                MANAGER_DN,
                Secret.fromString(MANAGER_SECRET));
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

        r.jenkins.setSecurityRealm(realm);
        //j.configRoundtrip();

        //ads verification
        User user = User.get("hhornblo", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), allOf(hasItem("HMS Lydia"), hasItem("ROLE_HMS LYDIA")));
        assertThat(user.getDisplayName(), is("Horatio Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        user = User.get("hnelson", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), allOf(hasItem("HMS Victory"), hasItem("ROLE_HMS VICTORY")));
        assertThat(user.getDisplayName(), is("Horatio Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));

        //Planet Express verification
        String content = r.createWebClient().login("fry", "fry").goTo("whoAmI").getBody().getTextContent();
        assertThat(content, containsString("Philip J. Fry"));
        user = User.get("fry", true, Collections.emptyMap());
        assertThat(user.getDisplayName(), is("Philip J. Fry"));


        LdapUserDetails zoidberg = (LdapUserDetails) r.jenkins.getSecurityRealm().loadUserByUsername2("zoidberg");
        assertEquals("cn=John A. Zoidberg,ou=people,dc=planetexpress,dc=com", zoidberg.getDn());

        user = r.jenkins.getUser("leela");
        String leelaEmail = MailAddressResolver.resolve(user);
        assertEquals("leela@planetexpress.com", leelaEmail);
        assertThat(user.getDisplayName(), is("Turanga Leela"));
    }
}
