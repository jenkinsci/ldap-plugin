package jenkins.security.plugins.ldap;

import hudson.security.LDAPSecurityRealm;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.junit.rules.RuleChain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

// Based on https://github.com/jenkinsci/configuration-as-code-plugin/blob/7766b7ef6153e3e210f257d323244c1f1470a10f/integrations/src/test/java/io/jenkins/plugins/casc/LDAPTest.java
public class CasCTest {
    @Rule
    public RuleChain chain = RuleChain.outerRule(new EnvironmentVariables()
            .set("LDAP_PASSWORD", "SECRET"))
            .around(new JenkinsConfiguredWithCodeRule());
    
    @Test
    @ConfiguredWithCode("casc.yml")
    public void configure_ldap() {
        final Jenkins jenkins = Jenkins.getInstance();
        final LDAPSecurityRealm securityRealm = (LDAPSecurityRealm) jenkins.getSecurityRealm();
        assertEquals(1, securityRealm.getConfigurations().size());
        assertTrue(securityRealm.getUserIdStrategy() instanceof IdStrategy.CaseInsensitive);
        assertTrue(securityRealm.getGroupIdStrategy() instanceof IdStrategy.CaseSensitive);
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
