package hudson.security.docker;

import hudson.Functions;
import hudson.security.LDAPSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import jenkins.security.plugins.ldap.LDAPConfiguration;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.io.FileUtils;
import org.jenkinsci.test.acceptance.docker.DockerContainer;
import org.jenkinsci.test.acceptance.docker.DockerFixture;
import org.jenkinsci.test.acceptance.docker.DockerRule;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TheFlintstonesTest {

    @Rule
    public DockerRule<TheFlintstones> docker = new DockerRule<>(TheFlintstones.class);

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Before
    public void setUp() throws Exception {
        Assume.assumeFalse(Functions.isWindows());
        TheFlintstones container = docker.get();
        while (!FileUtils.readFileToString(container.getLogfile(), StandardCharsets.UTF_8).contains("custom (exit status 0; expected)")) {
            Thread.sleep(1000);
        }
        LDAPConfiguration configuration = new LDAPConfiguration(
                container.ipBound(3268) + ':' + container.port(3268), "dc=samdom,dc=example,dc=com", false,
                "cn=Administrator,cn=Users,dc=samdom,dc=example,dc=com", Secret.fromString("ia4uV1EeKait"));
        configuration.setUserSearch("sAMAccountName={0}");
        configuration.setGroupSearchFilter("(&(objectclass=group)(cn={0}))");
        LDAPSecurityRealm realm = new LDAPSecurityRealm(Collections.singletonList(configuration), false, null, null, null);
        j.jenkins.setSecurityRealm(realm);
        UserDetails fred = null;
        for (int i = 0; i < 30 && fred == null; i++) {
            try {
                fred = realm.loadUserByUsername("fred");
            } catch (LdapDataAccessException ignored) {
                Thread.sleep(1000);
            }
        }
    }

    @Test
    public void userAttributesTest() throws IOException, InterruptedException {
        SecurityRealm realm = j.jenkins.getSecurityRealm();
        assertTrue(realm.loadUserByUsername("fred").isEnabled());
        assertFalse(realm.loadUserByUsername("wilma").isEnabled());
    }

    @DockerFixture(id = "ad-dc", ports = {135, 138, 445, 39, 464, 389, 3268}, udpPorts = {53}, matchHostPorts = true)
    public static class TheFlintstones extends DockerContainer {
    }
}
