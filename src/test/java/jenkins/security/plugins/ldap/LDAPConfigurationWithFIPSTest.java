package jenkins.security.plugins.ldap;

import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.security.FIPS140;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * Tests {@link LDAPConfiguration} in FIPS mode.
 */
public class LDAPConfigurationWithFIPSTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();

    @ClassRule
    public static FlagRule<String> fipsFlag = FlagRule.systemProperty(FIPS140.class.getName() + ".COMPLIANCE", "true");

    @Test
    public void managerPasswordUnderSizeInFipsModeTest() throws Exception {
        final String server = "localhost";
        final String rootDN = "ou=umich,dc=ou.edu";
        final String managerDN = "cn=admin,ou=umich,ou.edu";
        final String managerSecret = "secret";

        LDAPConfiguration.LDAPConfigurationDescriptor descriptor = new LDAPConfiguration.LDAPConfigurationDescriptor();
        FormValidation result = descriptor.doCheckServer(server, managerDN, Secret.fromString(managerSecret), rootDN);
        Assert.assertTrue(result.kind.name().equals("ERROR"));
        Assert.assertTrue(result.getMessage().equals(Messages.LDAPSecurityRealm_AuthenticationFailedNotFipsCompliantPass()));
    }

    @Test
    public void managerPasswordOverSizeInFipsModeTest() throws Exception {
        final String server = "localhost";
        final String rootDN = "ou=umich,dc=ou.edu";
        final String managerDN = "cn=admin,ou=umich,ou.edu";
        final String managerSecret = "passwordwithatleastfourteencaracters";

        LDAPConfiguration.LDAPConfigurationDescriptor descriptor = new LDAPConfiguration.LDAPConfigurationDescriptor();
        FormValidation result = descriptor.doCheckServer(server, managerDN, Secret.fromString(managerSecret), rootDN);
        Assert.assertTrue(result.kind.name().equals("ERROR"));
        Assert.assertFalse(result.getMessage().equals(Messages.LDAPSecurityRealm_AuthenticationFailedNotFipsCompliantPass()));
    }
}
