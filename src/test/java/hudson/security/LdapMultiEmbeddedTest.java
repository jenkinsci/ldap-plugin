package hudson.security;

import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.util.Secret;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.*;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.ArrayList;
import java.util.Arrays;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

/**
 * Tests connecting to two different embedded servers using slightly different configurations.
 */
@LDAPTestConfiguration
public class LdapMultiEmbeddedTest {
    public LDAPRule sevenSeas = new LDAPRule();
    public LDAPRule planetExpress = new LDAPRule();
    public JenkinsRule r = new JenkinsRule();
    @Rule
    public RuleChain chain = RuleChain.outerRule(sevenSeas).around(planetExpress).around(r);

    @Before
    public void setup() throws Exception {
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
    public void lookUp() {

        //Second server
        User user = User.get("hhornblo");
        assertThat(user.getAuthorities(), allOf(hasItem("HMS_Lydia"), hasItem("ROLE_HMS_LYDIA")));
        assertThat(user.getDisplayName(), is("Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        user = User.get("hnelson");
        assertThat(user.getAuthorities(), allOf(hasItem("HMS_Victory"), hasItem("ROLE_HMS_VICTORY")));
        assertThat(user.getDisplayName(), is("Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));

        //First server
        user = User.get("fry");
        assertThat(user.getAuthorities(), allOf(hasItem("crew"), hasItem("staff")));
        assertThat(user.getDisplayName(), is("Philip J. Fry"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("fry@planetexpress.com"));

        user = User.get("bender");
        assertThat(user.getAuthorities(), allOf(hasItem("crew"), hasItem("staff")));
        //Has something encrypted as cn
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("bender@planetexpress.com"));

        user = User.get("amy");
        assertThat(user.getAuthorities(), hasItem("staff"));
        assertThat(user.getDisplayName(), is("Amy Wong"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("amy@planetexpress.com"));

        user = User.get("professor");
        assertThat(user.getAuthorities(), allOf(hasItem("management"), hasItem("staff")));
        assertThat(user.getDisplayName(), is("Hubert J. Farnsworth"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("professor@planetexpress.com"));

    }

    @Test
    public void login() throws Exception {
        String content = r.createWebClient().login("fry", "fry").goTo("whoAmI").getBody().getTextContent();
        assertThat(content, containsString("Philip J. Fry"));

        content = r.createWebClient().login("hnelson", "pass").goTo("whoAmI").getBody().getTextContent();
        assertThat(content, containsString("Nelson"));
    }

    @Test
    public void loginWithBrokenServerInTheMiddle() throws Exception {
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
        try {
            r.createWebClient().login("hnelson", "pass");
            fail("hnelson should not be able to login because there is a broken server in between");
        } catch (com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException e) {
            assertEquals(401, e.getStatusCode());
        }

    }
}
