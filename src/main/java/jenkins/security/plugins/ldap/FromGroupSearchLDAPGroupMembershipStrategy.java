/*
 * The MIT License
 *
 * Copyright (c) 2014, Stephen Connolly
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
package jenkins.security.plugins.ldap;

import hudson.Extension;
import hudson.security.LDAPSecurityRealm;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.LdapUtils;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

/**
 * Traditional strategy.
 * @since 1.10
 */
public class FromGroupSearchLDAPGroupMembershipStrategy extends LDAPGroupMembershipStrategy {

    private static final Logger LOGGER = Logger.getLogger(FromGroupSearchLDAPGroupMembershipStrategy.class.getName());
    /**
     * The search filter to apply to groups. Only those groups matching this criteria will be considered as groups
     * that the user belongs to.
     *
     * Note: we leave the default blank for historical reasons.
     */
    private final String filter;

    @DataBoundConstructor
    public FromGroupSearchLDAPGroupMembershipStrategy(String filter) {
        this.filter = filter;
    }

    public String getFilter() {
        return filter;
    }

    @Override
    public void setAuthoritiesPopulator(LdapAuthoritiesPopulator authoritiesPopulator) {
        if (authoritiesPopulator instanceof LDAPSecurityRealm.AuthoritiesPopulatorImpl && StringUtils.isNotBlank(filter)) {
            ((LDAPSecurityRealm.AuthoritiesPopulatorImpl) authoritiesPopulator).setGroupSearchFilter(filter);
        }
        super.setAuthoritiesPopulator(authoritiesPopulator);
    }

    @Override
    public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username) {
        return getAuthoritiesPopulator().getGrantedAuthorities(userData, username);
    }

    @Override
    public Set<String> getGroupMembers(String groupDn, LDAPConfiguration conf) {
        LDAPExtendedTemplate template = conf.getLdapTemplate();
        String[] memberAttributes = { "member", "uniqueMember", "memberUid" };
        return template.executeReadOnly(ctx -> mapAttributes(groupDn, ctx.getAttributes(LdapUtils.getRelativeName(groupDn, ctx), memberAttributes)));
    }

    @Extension
    public static class DescriptorImpl extends LDAPGroupMembershipStrategyDescriptor {

        @Override
        public String getDisplayName() {
            return Messages.FromGroupSearchLDAPGroupMembershipStrategy_DisplayName();
        }
    }

    /**
     * Maps member attributes in groups to a set of member names.
     */
        private static Set<String> mapAttributes(String dn, Attributes attributes) throws NamingException {
            NamingEnumeration<?> enumeration;
            boolean expectingUidInsteadOfDn = false;
            if (attributes.get("member") != null) {
                enumeration = attributes.get("member").getAll();
            } else if (attributes.get("uniqueMember") != null) {
                enumeration = attributes.get("uniqueMember").getAll();
            } else if (attributes.get("memberUid") != null) {
                enumeration = attributes.get("memberUid").getAll();
                expectingUidInsteadOfDn = true;
            } else {
                LOGGER.log(Level.FINEST, "No members for {0}", dn);
                return Collections.emptySet();
            }
            Set<String> members = new TreeSet<>();
            while (enumeration.hasMore()) {
                String memberDn = String.valueOf(enumeration.next());
                if (expectingUidInsteadOfDn) {
                    members.add(memberDn);
                } else {
                    try {
                        LdapName memberName = new LdapName(memberDn);
                        members.add(String.valueOf(memberName.getRdn(memberName.size() - 1).getValue()));
                    } catch (InvalidNameException e) {
                        LOGGER.log(Level.FINEST, "Expecting DN but found {0}", memberDn);
                    }
                }
            }
            return members;
        }
}
