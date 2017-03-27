/*
 * The MIT License
 *
 * Copyright 2017 CloudBees,Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package hudson.security;

import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.util.Secret;
import jenkins.model.IdStrategy;
import jenkins.security.plugins.ldap.FromGroupSearchLDAPGroupMembershipStrategy;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

@LDAPConfiguration
public class LDAPEmbeddedTest {
    public LDAPRule ads = new LDAPRule();
    public JenkinsRule r = new JenkinsRule();
    @Rule
    public RuleChain chain = RuleChain.outerRule(ads).around(r);

    @Test
    @LDAPSchema(ldif = "sevenSeas", id = "sevenSeas", dn = "o=sevenSeas")
    public void userLookup() throws Exception {
        r.jenkins.setSecurityRealm(new LDAPSecurityRealm(
                ads.getUrl(),
                null,
                null,
                null,
                null,
                null,
                new FromGroupSearchLDAPGroupMembershipStrategy(null),
                "uid=admin,ou=system",
                Secret.fromString("pass"),
                false,
                false,
                new LDAPSecurityRealm.CacheConfiguration(100, 1000),
                new LDAPSecurityRealm.EnvironmentProperty[0],
                "cn",
                null,
                IdStrategy.CASE_INSENSITIVE,
                IdStrategy.CASE_INSENSITIVE)
        );
        User user = User.get("hhornblo");
        assertThat(user.getAuthorities(), allOf(hasItem("HMS Lydia"), hasItem("ROLE_HMS LYDIA")));
        assertThat(user.getDisplayName(), is("Horatio Hornblower"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hhornblo@royalnavy.mod.uk"));
        user = User.get("hnelson");
        assertThat(user.getAuthorities(), allOf(hasItem("HMS Victory"), hasItem("ROLE_HMS VICTORY")));
        assertThat(user.getDisplayName(), is("Horatio Nelson"));
        assertThat(user.getProperty(Mailer.UserProperty.class).getAddress(), is("hnelson@royalnavy.mod.uk"));
    }
}
