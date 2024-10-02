package hudson.security;

import java.util.logging.Level;

import hudson.util.Secret;
import jenkins.model.IdStrategy;
import jenkins.security.FIPS140;
import jenkins.security.plugins.ldap.FromUserRecordLDAPGroupMembershipStrategy;

import org.htmlunit.FailingHttpStatusCodeException;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;

public class LDAPSecurityRealmWithFIPSTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();
    @Rule
    public LoggerRule log = new LoggerRule();

    @ClassRule
    public static FlagRule<String> fipsFlag = FlagRule.systemProperty(FIPS140.class.getName() + ".COMPLIANCE", "true");

    @Test
    public void ldapAuthenticationWithFIPSTest() throws Exception {
        final String server = "ldaps://localhost";
        final String rootDN = "ou=umich,dc=ou.edu";
        final String userSearchBase = "cn=users,ou=umich,ou.edu";
        final String managerDN = "cn=admin,ou=umich,ou.edu";
        final String managerSecret = "secretsecretsecret";
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

        JenkinsRule.WebClient wc = r.createWebClient();

        log.record(LDAPSecurityRealm.class, Level.WARNING).capture(10); // reset
        FailingHttpStatusCodeException cannotLogin = assertThrows("Valid password, but expected to fail as there is no such user. Just 401",
                                                                  FailingHttpStatusCodeException.class,
                                                                  () -> wc.login("alice", "passwordLongEnoughToBeFIPScompliant"));
        assertThat("Invalid user", cannotLogin.getStatusCode(), is(401));

        log.record(LDAPSecurityRealm.class, Level.WARNING).capture(10); // reset
        cannotLogin = assertThrows("Short password, so the error is different now",
                                   FailingHttpStatusCodeException.class,
                                   () -> wc.login("bob", "shortPassword"));
        assertThat("Password invalid in FIPS, not even authenticated", cannotLogin.getStatusCode(), is(500));
        assertThat("FIPS message is logged", log, LoggerRule.recorded(Level.WARNING, containsString("the password must be at least 14 characters long")));
    }
}
