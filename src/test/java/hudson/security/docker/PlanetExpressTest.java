package hudson.security.docker;

import hudson.Functions;
import hudson.security.LDAPSecurityRealm;
import hudson.tasks.MailAddressResolver;
import hudson.util.Secret;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.jenkinsci.test.acceptance.docker.DockerContainer;
import org.jenkinsci.test.acceptance.docker.DockerFixture;
import org.jenkinsci.test.acceptance.docker.DockerRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeFalse;
import org.junit.BeforeClass;

/**
 * Tests the plugin when logging in to rroemhild/test-openldap
 */
public class PlanetExpressTest {

    @BeforeClass public static void linuxOnly() {
        assumeFalse("Windows CI builders now have Docker installed…but it does not support Linux images", Functions.isWindows() && System.getenv("JENKINS_URL") != null);
    }

    @Rule
    public DockerRule<PlanetExpress> docker = new DockerRule<>(PlanetExpress.class);
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void login() throws Exception {
        PlanetExpress d = docker.get();
        LDAPSecurityRealm realm = new LDAPSecurityRealm(d.getIpAddress(), PlanetExpress.DN, null, null, null, null, null, PlanetExpress.MANAGER_DN, Secret.fromString(PlanetExpress.MANAGER_SECRET), false, false, null, null, "cn", "mail", null,null);
        j.jenkins.setSecurityRealm(realm);
        j.configRoundtrip();
        String content = j.createWebClient().login("fry", "fry").goTo("whoAmI").getBody().getTextContent();
        assertThat(content, containsString("Philip J. Fry"));


        LdapUserDetails zoidberg = (LdapUserDetails) j.jenkins.getSecurityRealm().loadUserByUsername("zoidberg");
        assertEquals("cn=John A. Zoidberg,ou=people,dc=planetexpress,dc=com", zoidberg.getDn());

        String leelaEmail = MailAddressResolver.resolve(j.jenkins.getUser("leela"));
        assertEquals("leela@planetexpress.com", leelaEmail);

    }

    @DockerFixture(id = "openldap-express", ports = {389, 636})
    public static class PlanetExpress extends DockerContainer {

        static final String DN = "dc=planetexpress,dc=com";
        static final String MANAGER_DN = "cn=admin,dc=planetexpress,dc=com";
        static final String MANAGER_SECRET = "GoodNewsEveryone";

    }
}
