package hudson.security.docker;

import hudson.Functions;
import hudson.security.LDAPSecurityRealm;
import hudson.tasks.MailAddressResolver;
import hudson.util.Secret;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.RealJenkinsRule;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;

/**
 * Tests the plugin when logging in to rroemhild/test-openldap
 */
public class PlanetExpressTest {

    static final String TEST_IMAGE =
            "rroemhild/test-openldap:1.0@sha256:b4e433bbcba1f17899d6bcb0a8e854bbe52c754faa4e785d0c27a2b55eb12cd8";
    static final String DN = "dc=planetexpress,dc=com";
    static final String MANAGER_DN = "cn=admin,dc=planetexpress,dc=com";
    static final String MANAGER_SECRET = "GoodNewsEveryone";

    @BeforeClass public static void requiresDocker() {
        assumeTrue(DockerClientFactory.instance().isDockerAvailable());
    }

    @BeforeClass public static void linuxOnly() {
        assumeFalse("Windows CI builders now have Docker installed…but it does not support Linux images", Functions.isWindows() && System.getenv("JENKINS_URL") != null);
    }

    @SuppressWarnings("rawtypes")
    @Rule
    public GenericContainer container = new GenericContainer(TEST_IMAGE).withExposedPorts(389);

    @Rule
    public RealJenkinsRule rr = new RealJenkinsRule();

    @Test
    public void login() throws Throwable {
        String server = container.getHost() + ":" + container.getFirstMappedPort();
        rr.then(new Login(server));
    }
    private static class Login implements RealJenkinsRule.Step {
        private final String server;
        Login(String server) {
            this.server = server;
        }
        @Override
        public void run(JenkinsRule j) throws Throwable {
            LDAPSecurityRealm realm = new LDAPSecurityRealm(server, DN, null, null, null, null, null, MANAGER_DN, Secret.fromString(MANAGER_SECRET), false, false, null, null, "cn", "mail", null,null);
            j.jenkins.setSecurityRealm(realm);
            j.configRoundtrip();
            String content = j.createWebClient().login("fry", "fry").goTo("whoAmI").getBody().getTextContent();
            assertThat(content, containsString("Philip J. Fry"));

            LdapUserDetails zoidberg = (LdapUserDetails) j.jenkins.getSecurityRealm().loadUserByUsername2("zoidberg");
            assertEquals("cn=John A. Zoidberg,ou=people,dc=planetexpress,dc=com", zoidberg.getDn());

            String leelaEmail = MailAddressResolver.resolve(j.jenkins.getUser("leela"));
            assertEquals("leela@planetexpress.com", leelaEmail);
        }
    }

}
