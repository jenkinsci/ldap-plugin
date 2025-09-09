package hudson.security.docker;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import hudson.Functions;
import hudson.security.LDAPSecurityRealm;
import hudson.tasks.MailAddressResolver;
import hudson.util.Secret;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.RealJenkinsExtension;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Tests the plugin when logging in to rroemhild/test-openldap
 */
@Testcontainers(disabledWithoutDocker = true)
class PlanetExpressTest {

    private static final String TEST_IMAGE =
            "ghcr.io/rroemhild/docker-test-openldap:v2.5.0@sha256:3470e15c60119a1c0392cc162cdce71edfb42b55affdc69da574012f956317cd";
    private static final String DN = "dc=planetexpress,dc=com";
    private static final String MANAGER_DN = "cn=admin,dc=planetexpress,dc=com";
    private static final String MANAGER_SECRET = "GoodNewsEveryone";

    @RegisterExtension
    private final RealJenkinsExtension extension = new RealJenkinsExtension();

    @SuppressWarnings("rawtypes")
    @Container
    private final GenericContainer container = new GenericContainer(TEST_IMAGE).withExposedPorts(10389);

    @BeforeAll
    static void setUp() {
        assumeTrue(DockerClientFactory.instance().isDockerAvailable());
        assumeFalse(
                Functions.isWindows() && System.getenv("JENKINS_URL") != null,
                "Windows CI builders now have Docker installed…but it does not support Linux images");
    }

    @Test
    void login() throws Throwable {
        String server = container.getHost() + ":" + container.getFirstMappedPort();
        extension.then(new Login(server));
    }

    private static class Login implements RealJenkinsExtension.Step {

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
