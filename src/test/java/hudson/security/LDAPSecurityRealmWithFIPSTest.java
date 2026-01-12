package hudson.security;

import java.util.logging.Level;

import hudson.util.Secret;
import jenkins.model.IdStrategy;
import jenkins.security.FIPS140;
import jenkins.security.plugins.ldap.FromUserRecordLDAPGroupMembershipStrategy;

import org.htmlunit.FailingHttpStatusCodeException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LogRecorder;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

@WithJenkins
class LDAPSecurityRealmWithFIPSTest {

    private JenkinsRule r;

    private final LogRecorder log = new LogRecorder();

    private static String fipsFlag;

    @BeforeAll
    static void beforeAll() {
        fipsFlag = System.setProperty(FIPS140.class.getName() + ".COMPLIANCE", "true");
    }

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        r = rule;
    }

    @AfterAll
    static void afterAll() {
        if (fipsFlag != null) {
            System.setProperty(FIPS140.class.getName() + ".COMPLIANCE", fipsFlag);
        } else  {
            System.clearProperty(FIPS140.class.getName() + ".COMPLIANCE");
        }
    }

    @Test
    void ldapAuthenticationWithFIPSTest() {
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
        FailingHttpStatusCodeException cannotLogin = assertThrows(FailingHttpStatusCodeException.class,
                                                                  () -> wc.login("alice", "passwordLongEnoughToBeFIPScompliant"),
                                                                  "Valid password, but expected to fail as there is no such user. Just 401");
        assertThat("Invalid user", cannotLogin.getStatusCode(), is(401));

        log.record(LDAPSecurityRealm.class, Level.WARNING).capture(10); // reset
        cannotLogin = assertThrows(FailingHttpStatusCodeException.class,
                                   () -> wc.login("bob", "shortPassword"),
                                   "Short password, so the error is different now");
        assertThat("Password invalid in FIPS, not even authenticated", cannotLogin.getStatusCode(), is(500));
        assertThat("FIPS message is logged", log, LogRecorder.recorded(Level.WARNING, containsString("the password must be at least 14 characters long")));
    }
}
