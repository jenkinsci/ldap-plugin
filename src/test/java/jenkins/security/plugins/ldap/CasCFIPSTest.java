package jenkins.security.plugins.ldap;

import hudson.security.LDAPSecurityRealm;
import hudson.util.FormValidation;
import hudson.util.Secret;
import io.jenkins.plugins.casc.ConfiguratorException;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.junit.rules.ExpectedException;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.FlagRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.*;

/**
 * Based on {@link jenkins.security.plugins.ldap.CasCTest}
 */
public class CasCFIPSTest {
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    @ClassRule
    public static FlagRule<String> fipsSystemPropertyRule =
            FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");

    @Rule
    public RuleChain chain = RuleChain.outerRule(new EnvironmentVariables()
                    .set("LDAP_PASSWORD", "SECRET_Password_123"))
            .around(new JenkinsConfiguredWithCodeRule());

    @Test
    @ConfiguredWithCode("casc_ldap_secure.yml")
    public void configure_ldap() {
        final LDAPSecurityRealm securityRealm = (LDAPSecurityRealm) Jenkins.get().getSecurityRealm();
        assertEquals(1, securityRealm.getConfigurations().size());
        assertTrue(securityRealm.getUserIdStrategy() instanceof IdStrategy.CaseInsensitive);
        assertTrue(securityRealm.getGroupIdStrategy() instanceof IdStrategy.CaseSensitive);
        final LDAPConfiguration configuration = securityRealm.getConfigurations().get(0);
        assertEquals("ldaps://ldap.acme.com", configuration.getServer());
        assertEquals("SECRET_Password_123", configuration.getManagerPassword());
        assertEquals("manager", configuration.getManagerDN());
        assertEquals("(&(objectCategory=User)(sAMAccountName={0}))", configuration.getUserSearch());
        assertEquals("(&(cn={0})(objectclass=group))", configuration.getGroupSearchFilter());
        final FromGroupSearchLDAPGroupMembershipStrategy strategy = ((FromGroupSearchLDAPGroupMembershipStrategy) configuration.getGroupMembershipStrategy());
        assertEquals("(&(objectClass=group)(|(cn=GROUP_1)(cn=GROUP_2)))", strategy.getFilter());
    }

    /**
     * Expect an exception when LDAP url is not secure & FIPS is enabled
     */
    @Test
    @ConfiguredWithCode(value = "casc.yml", expected = ConfiguratorException.class)
    public void configure_ldap_for_invalid() {
        // This test is expected to throw an ConfiguratorException while loading the configuration itself
        // because the LDAP URL is not secure and FIPS is enabled. Hence, the code block is empty.
    }

    @Test
    public void testPasswordCheck(){
        // Test with a short password
        FormValidation shortPasswordValidation = new LDAPConfiguration.LDAPConfigurationDescriptor().doCheckManagerPasswordSecret(Secret.fromString("short"));
        assertEquals(FormValidation.Kind.ERROR, shortPasswordValidation.kind);
        assertThat(shortPasswordValidation.getMessage(), containsString("Password is too short"));

        // Test with a strong password but server validation fails hence checking for 'Unknown host'
        FormValidation strongPasswordValidation = new LDAPConfiguration.LDAPConfigurationDescriptor().doCheckManagerPasswordSecret(Secret.fromString("ThisIsVeryStrongPassword"));
        assertEquals(FormValidation.Kind.OK, strongPasswordValidation.kind);

        //Test when password is null
        LDAPConfiguration configuration = new LDAPConfiguration("ldaps://ldap.example.com", "dc=example,dc=com", true, null, null);
        assertNotNull(configuration);

        // Test with a short password
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Password is too short");
        new LDAPConfiguration("ldaps://ldap.example.com", "dc=example,dc=com", true, null, Secret.fromString("shortString"));

        //Test with a strong password
        configuration = new LDAPConfiguration("ldaps://ldap.example.com", "dc=example,dc=com", true, null, Secret.fromString("ThisIsVeryStrongPassword"));
        assertNotNull(configuration);
    }

    @Test
    public void testInSecureServerUrl(){
        // Test with an invalid server URL
        FormValidation invalidServerValidation = new LDAPConfiguration.LDAPConfigurationDescriptor().doCheckServer("invalid-url", "dc=example,dc=com", Secret.fromString("SomePwd"), null);
        assertEquals(FormValidation.Kind.ERROR, invalidServerValidation.kind);
        assertThat(invalidServerValidation.getMessage(), containsString("LDAP server URL is not secure"));
    }
}
