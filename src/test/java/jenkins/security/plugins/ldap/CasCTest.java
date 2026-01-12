package jenkins.security.plugins.ldap;

import hudson.security.LDAPSecurityRealm;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

// Based on https://github.com/jenkinsci/configuration-as-code-plugin/blob/7766b7ef6153e3e210f257d323244c1f1470a10f/integrations/src/test/java/io/jenkins/plugins/casc/LDAPTest.java
@WithJenkinsConfiguredWithCode
class CasCTest {

    @BeforeAll
    static void beforeAll() {
        System.setProperty("LDAP_PASSWORD", "SECRET");
    }

    @AfterAll
    static void afterAll() {
        System.clearProperty("LDAP_PASSWORD");
    }

    @Test
    @ConfiguredWithCode("casc.yml")
    void configure_ldap(JenkinsConfiguredWithCodeRule j) {
        final LDAPSecurityRealm securityRealm = (LDAPSecurityRealm) Jenkins.get().getSecurityRealm();
        assertEquals(1, securityRealm.getConfigurations().size());
        assertInstanceOf(IdStrategy.CaseInsensitive.class, securityRealm.getUserIdStrategy());
        assertInstanceOf(IdStrategy.CaseSensitive.class, securityRealm.getGroupIdStrategy());
        final LDAPConfiguration configuration = securityRealm.getConfigurations().get(0);
        assertEquals("ldap.acme.com", configuration.getServer());
        assertEquals("SECRET", configuration.getManagerPassword());
        assertEquals("manager", configuration.getManagerDN());
        assertEquals("(&(objectCategory=User)(sAMAccountName={0}))", configuration.getUserSearch());
        assertEquals("(&(cn={0})(objectclass=group))", configuration.getGroupSearchFilter());
        final FromGroupSearchLDAPGroupMembershipStrategy strategy = ((FromGroupSearchLDAPGroupMembershipStrategy) configuration.getGroupMembershipStrategy());
        assertEquals("(&(objectClass=group)(|(cn=GROUP_1)(cn=GROUP_2)))", strategy.getFilter());
    }
}
