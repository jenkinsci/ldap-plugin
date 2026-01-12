package jenkins.security.plugins.ldap;

import hudson.security.LDAPSecurityRealm;
import hudson.util.FormValidation;
import hudson.util.Secret;
import io.jenkins.plugins.casc.ConfiguratorException;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredRule;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import jenkins.security.FIPS140;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Based on {@link jenkins.security.plugins.ldap.CasCTest}
 */
@WithJenkinsConfiguredWithCode
class CasCFIPSTest {

    private static String fipsFlag;

    @BeforeAll
    static void beforeAll() {
        fipsFlag = System.setProperty(FIPS140.class.getName() + ".COMPLIANCE", "true");
        System.setProperty("LDAP_PASSWORD", "SECRET");
    }

    @AfterAll
    static void afterAll() {
        if (fipsFlag != null) {
            System.setProperty(FIPS140.class.getName() + ".COMPLIANCE", fipsFlag);
        } else  {
            System.clearProperty(FIPS140.class.getName() + ".COMPLIANCE");
        }
        System.clearProperty("LDAP_PASSWORD");
    }

    @Test
    @ConfiguredWithCode("casc_ldap_secure.yml")
    void configure_ldap(JenkinsConfiguredWithCodeRule r) {
        final LDAPSecurityRealm securityRealm = (LDAPSecurityRealm) Jenkins.get().getSecurityRealm();
        assertEquals(1, securityRealm.getConfigurations().size());
        assertInstanceOf(IdStrategy.CaseInsensitive.class, securityRealm.getUserIdStrategy());
        assertInstanceOf(IdStrategy.CaseSensitive.class, securityRealm.getGroupIdStrategy());
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
    void configure_ldap_for_invalid(JenkinsConfiguredWithCodeRule r) {
        // This test is expected to throw an ConfiguratorException while loading the configuration itself
        // because the LDAP URL is not secure and FIPS is enabled. Hence, the code block is empty.
    }

    @Test
    void testPasswordCheck(JenkinsConfiguredWithCodeRule r) {
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

        Throwable exception = assertThrows(IllegalArgumentException.class, () -> new LDAPConfiguration("ldaps://ldap.example.com", "dc=example,dc=com", true, null, Secret.fromString("shortString")));

        //Test with a strong password
        configuration = new LDAPConfiguration("ldaps://ldap.example.com", "dc=example,dc=com", true, null, Secret.fromString("ThisIsVeryStrongPassword"));
        assertNotNull(configuration);

        assertThat(exception.getMessage(), org.hamcrest.CoreMatchers.containsString("Password is too short"));
    }

    @Test
    void testInSecureServerUrl(JenkinsConfiguredWithCodeRule r) {
        // Test with an invalid server URL
        FormValidation invalidServerValidation = new LDAPConfiguration.LDAPConfigurationDescriptor().doCheckServer("invalid-url", "dc=example,dc=com", Secret.fromString("SomePwd"), null);
        assertEquals(FormValidation.Kind.ERROR, invalidServerValidation.kind);
        assertThat(invalidServerValidation.getMessage(), containsString("LDAP server URL is not secure"));
    }
}
