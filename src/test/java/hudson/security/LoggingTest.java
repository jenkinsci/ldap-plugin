package hudson.security;

import hudson.util.Secret;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.CaptureLogRule;
import jenkins.security.plugins.ldap.FromGroupSearchLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.FromUserRecordLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.LDAPConfiguration;
import jenkins.security.plugins.ldap.LDAPRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Arrays;
import java.util.logging.Level;

public class LoggingTest {
    public LDAPRule sevenSeas = new LDAPRule();
    public LDAPRule planetExpress = new LDAPRule();
    public JenkinsRule r = new JenkinsRule();
    public CaptureLogRule log = new CaptureLogRule(LDAPSecurityRealm.class.getName(), Level.WARNING);
    @Rule
    public RuleChain chain = RuleChain.outerRule(sevenSeas).around(planetExpress).around(r).around(log);

    @Before
    public void setup() throws Exception {
        sevenSeas.loadSchema("sevenSeas", "o=sevenSeas", getClass().getResourceAsStream("/hudson/security/sevenSeas.ldif"));
        planetExpress.loadSchema("planetexpress", "dc=planetexpress,dc=com", getClass().getResourceAsStream("/hudson/security/planetexpress.ldif"));
    }

    public void setupConfiguration(boolean sevenSeasPwd, boolean planetExpressPwd) {
        final Secret sevenSeasPass = sevenSeasPwd ? Secret.fromString("pass") : Secret.fromString("something completely wrong");
        LDAPConfiguration sevenSeasConf = new LDAPConfiguration(
                sevenSeas.getUrl(),
                null,
                false,
                "uid=admin,ou=system",
                sevenSeasPass);
        sevenSeasConf.setUserSearchBase("ou=people,o=sevenSeas");
        sevenSeasConf.setUserSearch(null);
        sevenSeasConf.setGroupSearchBase("ou=groups,o=sevenSeas");
        sevenSeasConf.setGroupSearchFilter(null);
        sevenSeasConf.setGroupMembershipStrategy(new FromUserRecordLDAPGroupMembershipStrategy("memberof"));
        sevenSeasConf.setDisplayNameAttributeName("sn"); //Different than the next so we can see that difference is made
        sevenSeasConf.setMailAddressAttributeName(null);

        final Secret planetExpressPass = planetExpressPwd ? Secret.fromString("pass") : Secret.fromString("something completely wrong");
        LDAPConfiguration planetExpressConf = new LDAPConfiguration(
                planetExpress.getUrl(),
                "dc=planetexpress,dc=com",
                false,
                "uid=admin,ou=system",
                planetExpressPass);
        planetExpressConf.setUserSearchBase("ou=people");
        planetExpressConf.setUserSearch(null);
        planetExpressConf.setGroupSearchBase("ou=groups");
        planetExpressConf.setGroupSearchFilter(null);
        planetExpressConf.setGroupMembershipStrategy(new FromGroupSearchLDAPGroupMembershipStrategy("uniquemember={0}"));
        planetExpressConf.setDisplayNameAttributeName("cn"); //Different than the first so we can see that difference is made
        planetExpressConf.setMailAddressAttributeName("mail");


        r.jenkins.setSecurityRealm(new LDAPSecurityRealm(
                Arrays.asList(planetExpressConf,sevenSeasConf),
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE)
        );
    }

    @Test
    public void when_first_is_wrong_and_login_on_first_then_log() {
        setupConfiguration(false, true);
    }

    @Test
    public void when_first_is_wrong_and_login_on_second_then_log() {
        setupConfiguration(false, true);
    }

    @Test
    public void when_second_is_wrong_and_login_on_second_then_log() {
        setupConfiguration(true, false);
    }

    @Test
    public void when_second_is_wrong_and_login_on_first_no_log() {
        setupConfiguration(true, false);
    }


    @Test
    public void when_first_is_wrong_and_lookup_on_first_then_log() {
        setupConfiguration(false, true);
    }

    @Test
    public void when_first_is_wrong_and_lookup_on_second_then_log() {
        setupConfiguration(false, true);
    }

    @Test
    public void when_second_is_wrong_and_lookup_on_second_then_log() {
        setupConfiguration(true, false);
    }

    @Test
    public void when_second_is_wrong_and_lookup_on_first_no_log() {
        setupConfiguration(true, false);
    }
}
