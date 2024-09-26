package hudson.security;

import hudson.util.Secret;
import jenkins.model.IdStrategy;
import jenkins.security.FIPS140;
import jenkins.security.plugins.ldap.FromUserRecordLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.LDAPConfiguration;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsRule;

public class LDAPSecurityRealmWithFIPSTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();


    @ClassRule
    public static FlagRule<String> fipsFlag = FlagRule.systemProperty(FIPS140.class.getName() + ".COMPLIANCE", "true");

    @Test
    public void ldapAuthenticationWithFIPSTest() throws Exception {
        final String server = "localhost";
        final String rootDN = "ou=umich,dc=ou.edu";
        final String userSearchBase = "cn=users,ou=umich,ou.edu";
        final String managerDN = "cn=admin,ou=umich,ou.edu";
        final String managerSecret = "secret";
        final LDAPSecurityRealm realm = new LDAPSecurityRealm(
                server,
                rootDN,
                userSearchBase,
                null,
                null,
                null,
                new FromUserRecordLDAPGroupMembershipStrategy("previousValue"),
                managerDN,
                Secret.fromString(managerSecret),
                false,
                false,
                null,
                null,
                null,
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE);
        r.jenkins.setSecurityRealm(realm);
        //realm.authenticate2("user","secret");
    }
}
