package hudson.security;

import org.htmlunit.FailingHttpStatusCodeException;
import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.util.Secret;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.*;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.LogRecorder;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.jvnet.hudson.test.LogRecorder.recorded;

/**
 * Tests connecting to two different embedded servers using slightly different configurations.
 */
@LDAPTestConfiguration
@WithJenkins
class LdapMultiEmbeddedTest {

    @RegisterExtension
    private final LDAPExtension sevenSeas = new LDAPExtension();
    @RegisterExtension
    private final LDAPExtension planetExpress = new LDAPExtension();
    private JenkinsRule r;

    private final LogRecorder log = new LogRecorder().record(LDAPSecurityRealm.class, Level.WARNING).capture(100);

    @BeforeEach
    void beforeEach(JenkinsRule rule) throws Exception {
        r = rule;
        sevenSeas.loadSchema("sevenSeas", "o=sevenSeas", getClass().getResourceAsStream("/hudson/security/sevenSeas.ldif"));
        planetExpress.loadSchema("planetexpress", "dc=planetexpress,dc=com", getClass().getResourceAsStream("/hudson/security/planetexpress.ldif"));

        LDAPConfiguration sevenSeasConf = new LDAPConfiguration(
                sevenSeas.getUrl(),
                null,
                false,
                "uid=admin,ou=system",
                Secret.fromString("pass"));
        sevenSeasConf.setUserSearchBase("ou=people,o=sevenSeas");
        sevenSeasConf.setUserSearch(null);
        sevenSeasConf.setGroupSearchBase("ou=groups,o=sevenSeas");
        sevenSeasConf.setGroupSearchFilter(null);
        sevenSeasConf.setGroupMembershipStrategy(new FromUserRecordLDAPGroupMembershipStrategy("memberof"));
        sevenSeasConf.setDisplayNameAttributeName("sn"); //Different than the next so we can see that difference is made
        sevenSeasConf.setMailAddressAttributeName(null);

        LDAPConfiguration planetExpressConf = new LDAPConfiguration(planetExpress.getUrl(), "dc=planetexpress,dc=com", false, "uid=admin,ou=system", Secret.fromString("pass"));
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
    void lookUp() {

        //Second server
        User user = User.get("hhornblo", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), allOf(hasItem("HMS_Lydia"), hasItem("ROLE_HMS_LYDIA")));
        assertThat(user.getDisplayName(), is("Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        user = User.get("hnelson", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), allOf(hasItem("HMS_Victory"), hasItem("ROLE_HMS_VICTORY")));
        assertThat(user.getDisplayName(), is("Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));

        //First server
        user = User.get("fry", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), allOf(hasItem("crew"), hasItem("staff")));
        assertThat(user.getDisplayName(), is("Philip J. Fry"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("fry@planetexpress.com"));

        user = User.get("bender", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), allOf(hasItem("crew"), hasItem("staff")));
        //Has something encrypted as cn
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("bender@planetexpress.com"));

        user = User.get("amy", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), hasItem("staff"));
        assertThat(user.getDisplayName(), is("Amy Wong"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("amy@planetexpress.com"));

        user = User.get("professor", true, Collections.emptyMap());
        assertThat(user.getAuthorities(), allOf(hasItem("management"), hasItem("staff")));
        assertThat(user.getDisplayName(), is("Hubert J. Farnsworth"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("professor@planetexpress.com"));

    }

    @Test
    void login() throws Exception {
        String content = r.createWebClient().login("fry", "fry").goTo("whoAmI").getBody().getTextContent();
        assertThat(content, containsString("Philip J. Fry"));

        content = r.createWebClient().login("hnelson", "pass").goTo("whoAmI").getBody().getTextContent();
        assertThat(content, containsString("Nelson"));
    }

    @Test
    void loginWithBrokenServerInTheMiddle() throws Exception {
        //Insert a bad configuration in the middle
        LDAPSecurityRealm realm = (LDAPSecurityRealm) r.jenkins.getSecurityRealm();
        ArrayList<LDAPConfiguration> newList = new ArrayList<>(realm.getConfigurations());
        newList.add(1, new LDAPConfiguration("foobar.example.com", "dc=foobar,dc=example,dc=com", false, null, null));
        LDAPSecurityRealm newRealm = new LDAPSecurityRealm(newList, realm.disableMailAddressResolver, realm.getCache(), realm.getUserIdStrategy(), realm.getGroupIdStrategy());
        r.jenkins.setSecurityRealm(newRealm);

        //Fry should be able to log in
        String content = r.createWebClient().login("fry", "fry").goTo("whoAmI").getBody().getTextContent();
        assertThat(content, containsString("Philip J. Fry"));
        //hnelson should not
        FailingHttpStatusCodeException e = assertThrows(FailingHttpStatusCodeException.class, () -> r.createWebClient().login("hnelson", "pass"),
                "hnelson should not be able to login because there is a broken server in between");
        assertEquals(401, e.getStatusCode());
    }

    private static final String FAILED_COMMUNICATION_WITH_LDAP_SERVER = "Failed communication with ldap server";
    private static final String WILL_NOT_TRY_NEXT_CONFIGURATION = ", will _not_ try the next configuration";
    private static final String WILL_TRY_NEXT_CONFIGURATION = ", will try the next configuration";
    private static final String INVALID_URL_PREFIX = "ldap://invalid_host_for_testing:";

    private void setBadPwd(LDAPExtension rule) {
        reconfigure(rule, EnumSet.of(LdapConfigOption.BAD_PASSWORD));
    }

    private enum LdapConfigOption {
        BAD_PASSWORD, BAD_SERVER_URL, IGNORE_IF_UNAVAILABLE
    }

    private void reconfigure(LDAPExtension rule, Set<LdapConfigOption> options) {
        final LDAPSecurityRealm realm = (LDAPSecurityRealm)r.jenkins.getSecurityRealm();
        LDAPConfiguration repl = null;
        int index = -1;
        final List<LDAPConfiguration> configurations = realm.getConfigurations();
        for (int i = 0; i < configurations.size(); i++) {
            LDAPConfiguration configuration = configurations.get(i);
            if (configuration.getServer().equals(rule.getUrl())) {
                repl = configuration;
                index = i;
                break;
            }
        }
        assertNotNull(repl);
        assertTrue(index >= 0);

        LDAPConfiguration nc = new LDAPConfiguration(
                options.contains(LdapConfigOption.BAD_SERVER_URL)
                        ? INVALID_URL_PREFIX + rule.getPort()
                        : repl.getServer(),
                repl.getRootDN(),
                true,
                repl.getManagerDN(),
                options.contains(LdapConfigOption.BAD_PASSWORD)
                        ? Secret.fromString("something completely wrong")
                        : repl.getManagerPasswordSecret());
        if (options.contains(LdapConfigOption.IGNORE_IF_UNAVAILABLE)) {
            nc.setIgnoreIfUnavailable(true);
        }
        configurations.set(index, nc);
        r.jenkins.setSecurityRealm(new LDAPSecurityRealm(configurations,
                realm.disableMailAddressResolver,
                realm.getCache(),
                realm.getUserIdStrategy(),
                realm.getGroupIdStrategy()));
    }

    @Test
    void when_first_is_wrong_and_login_on_first_then_log() {
        setBadPwd(planetExpress);
        FailingHttpStatusCodeException e = assertThrows(FailingHttpStatusCodeException.class, () -> r.createWebClient().login("fry", "fry"), "Login should fail");
        assertEquals(401, e.getStatusCode());

        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(planetExpress.getUrl())),
                CoreMatchers.instanceOf(AuthenticationServiceException.class)));
    }

    @Test
    void when_first_is_wrong_and_login_on_second_then_log() {
        setBadPwd(planetExpress);
        FailingHttpStatusCodeException e = assertThrows(FailingHttpStatusCodeException.class, () -> r.createWebClient().login("hnelson", "pass"), "Login should fail");
        assertEquals(401, e.getStatusCode());

        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(planetExpress.getUrl())),
                CoreMatchers.instanceOf(AuthenticationServiceException.class)));
    }

    @Test
    void when_second_is_wrong_and_login_on_second_then_log() {
        setBadPwd(sevenSeas);
        FailingHttpStatusCodeException e = assertThrows(FailingHttpStatusCodeException.class, () -> r.createWebClient().login("hnelson", "pass"), "Login should fail");
        assertEquals(401, e.getStatusCode());

        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(sevenSeas.getUrl())),
                CoreMatchers.instanceOf(AuthenticationServiceException.class)));
    }

    @Test
    void when_second_is_wrong_and_login_on_first_no_log() throws Exception {
        setBadPwd(sevenSeas);
        r.createWebClient().login("fry", "fry");

        assertThat(log, not(recorded(Level.WARNING,
                containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER))));
    }


    @Test
    void when_first_is_wrong_and_lookup_on_first_then_log() {
        setBadPwd(planetExpress);

        try {
            r.jenkins.getSecurityRealm().loadUserByUsername2("fry");
        } catch (UserMayOrMayNotExistException2 e) {
            //all is as expected
        }
        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_NOT_TRY_NEXT_CONFIGURATION),
                        containsString(planetExpress.getUrl())),
                CoreMatchers.instanceOf(UserMayOrMayNotExistException2.class)));
    }

    @Test
    void when_first_is_wrong_and_lookup_on_second_then_log() {
        setBadPwd(planetExpress);
        assertThrows(UserMayOrMayNotExistException2.class, () -> r.jenkins.getSecurityRealm().loadUserByUsername2("hnelson"));

        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_NOT_TRY_NEXT_CONFIGURATION),
                        containsString(planetExpress.getUrl())),
                CoreMatchers.instanceOf(UserMayOrMayNotExistException2.class)));
    }

    @Test
    void when_second_is_wrong_and_lookup_on_second_then_log() {
        setBadPwd(sevenSeas);
        assertThrows(UserMayOrMayNotExistException2.class, () -> r.jenkins.getSecurityRealm().loadUserByUsername2("hnelson"));

        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_NOT_TRY_NEXT_CONFIGURATION),
                        containsString(sevenSeas.getUrl())),
                CoreMatchers.instanceOf(UserMayOrMayNotExistException2.class)));
    }

    @Test
    void when_second_is_wrong_and_lookup_on_first_no_log() {
        setBadPwd(sevenSeas);
        assertDoesNotThrow(() -> {
            r.jenkins.getSecurityRealm().loadUserByUsername2("fry");
        }, "No exception should be thrown when first is working");
        assertThat(log, not(recorded(Level.WARNING,
                containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER))));
    }

    @Test
    void when_first_is_unavailable_and_login_on_second_then_no_login() {
        reconfigure(planetExpress, EnumSet.of(LdapConfigOption.BAD_SERVER_URL));
        FailingHttpStatusCodeException e = assertThrows(FailingHttpStatusCodeException.class, () -> r.createWebClient().login("hnelson", "pass"), "Login should fail");
        assertEquals(401, e.getStatusCode());

        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_NOT_TRY_NEXT_CONFIGURATION),
                        containsString(INVALID_URL_PREFIX + planetExpress.getPort())),
                CoreMatchers.instanceOf(AuthenticationServiceException.class)));
    }

    @Test
    void when_first_is_wrong_and_ignorable_and_login_on_second_then_login() throws Exception {
        reconfigure(planetExpress, EnumSet.of(LdapConfigOption.BAD_PASSWORD, LdapConfigOption.IGNORE_IF_UNAVAILABLE));
        r.createWebClient().login("hnelson", "pass");
        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_TRY_NEXT_CONFIGURATION),
                        containsString(planetExpress.getUrl())),
                CoreMatchers.instanceOf(UserMayOrMayNotExistException2.class)));
    }

    @Test
    void when_first_is_unavailable_and_ignorable_and_login_on_second_then_login() throws Exception {
        reconfigure(planetExpress, EnumSet.of(LdapConfigOption.BAD_SERVER_URL, LdapConfigOption.IGNORE_IF_UNAVAILABLE));
        r.createWebClient().login("hnelson", "pass");
        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_TRY_NEXT_CONFIGURATION),
                        containsString(INVALID_URL_PREFIX + planetExpress.getPort())),
                CoreMatchers.instanceOf(UserMayOrMayNotExistException2.class)));
    }

    @Test
    void when_first_and_second_are_unavailable_and_ignorable_then_no_login() {
        reconfigure(planetExpress, EnumSet.of(LdapConfigOption.BAD_SERVER_URL, LdapConfigOption.IGNORE_IF_UNAVAILABLE));
        reconfigure(sevenSeas, EnumSet.of(LdapConfigOption.BAD_SERVER_URL, LdapConfigOption.IGNORE_IF_UNAVAILABLE));
        FailingHttpStatusCodeException e = assertThrows(FailingHttpStatusCodeException.class, () -> r.createWebClient().login("hnelson", "pass"), "Login should fail");
        assertEquals(401, e.getStatusCode());

        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_TRY_NEXT_CONFIGURATION),
                        containsString(INVALID_URL_PREFIX + planetExpress.getPort())),
                CoreMatchers.instanceOf(AuthenticationServiceException.class)));
        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_TRY_NEXT_CONFIGURATION),
                        containsString(INVALID_URL_PREFIX + sevenSeas.getPort())),
                CoreMatchers.instanceOf(AuthenticationServiceException.class)));
    }

    @Test
    void when_first_is_wrong_but_ignorable_and_lookup_on_second_then_success() {
        reconfigure(planetExpress, EnumSet.of(LdapConfigOption.BAD_PASSWORD, LdapConfigOption.IGNORE_IF_UNAVAILABLE));
        assertThat(r.jenkins.getSecurityRealm().loadUserByUsername2("hnelson"), notNullValue());
        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_TRY_NEXT_CONFIGURATION),
                        containsString(planetExpress.getUrl())),
                CoreMatchers.instanceOf(UserMayOrMayNotExistException2.class)));
    }

    @Test
    void when_first_and_second_are_unavailable_and_ignorable_then_lookup_fails() {
        reconfigure(planetExpress, EnumSet.of(LdapConfigOption.BAD_SERVER_URL, LdapConfigOption.IGNORE_IF_UNAVAILABLE));
        reconfigure(sevenSeas, EnumSet.of(LdapConfigOption.BAD_SERVER_URL, LdapConfigOption.IGNORE_IF_UNAVAILABLE));
        assertThrows(UsernameNotFoundException.class, () -> r.jenkins.getSecurityRealm().loadUserByUsername2("hnelson"));

        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_TRY_NEXT_CONFIGURATION),
                        containsString(INVALID_URL_PREFIX + planetExpress.getPort())),
                CoreMatchers.instanceOf(UserMayOrMayNotExistException2.class)));
        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_TRY_NEXT_CONFIGURATION),
                        containsString(INVALID_URL_PREFIX + sevenSeas.getPort())),
                CoreMatchers.instanceOf(UserMayOrMayNotExistException2.class)));
    }

    @Test
    void when_second_is_wrong_and_lookup_group_on_second_then_log() {
        setBadPwd(sevenSeas);
        assertThrows(UserMayOrMayNotExistException2.class, () -> r.jenkins.getSecurityRealm().loadGroupByGroupname2("HMS Victory", false));

        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(sevenSeas.getUrl())),
                CoreMatchers.instanceOf(UserMayOrMayNotExistException2.class)));
    }

    @Test
    void when_first_is_wrong_and_lookup_group_on_second_then_failure() {
        reconfigure(planetExpress, EnumSet.of(LdapConfigOption.BAD_PASSWORD));
        assertThrows(UserMayOrMayNotExistException2.class, () -> r.jenkins.getSecurityRealm().loadGroupByGroupname2("HMS Lydia", false));

        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_NOT_TRY_NEXT_CONFIGURATION),
                        containsString(planetExpress.getUrl())),
                CoreMatchers.instanceOf(UserMayOrMayNotExistException2.class)));
    }

    @Test
    void when_first_is_wrong_but_ignorable_and_lookup_group_on_second_then_success() {
        reconfigure(planetExpress, EnumSet.of(LdapConfigOption.BAD_PASSWORD, LdapConfigOption.IGNORE_IF_UNAVAILABLE));
        assertThat(r.jenkins.getSecurityRealm().loadGroupByGroupname2("HMS Lydia", false), notNullValue());
        assertThat(log, recorded(Level.WARNING,
                allOf(containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER),
                        containsString(WILL_TRY_NEXT_CONFIGURATION),
                        containsString(planetExpress.getUrl())),
                CoreMatchers.instanceOf(UserMayOrMayNotExistException2.class)));
    }

    @Test
    void when_second_is_wrong_and_lookup_group_on_first_then_no_log() {
        setBadPwd(sevenSeas);
        assertDoesNotThrow(() -> {
            r.jenkins.getSecurityRealm().loadGroupByGroupname2("crew", false);
        }, "No exception should be thrown when first is working");
        assertThat(log, not(recorded(Level.WARNING,
                containsString(FAILED_COMMUNICATION_WITH_LDAP_SERVER))));
    }
}
