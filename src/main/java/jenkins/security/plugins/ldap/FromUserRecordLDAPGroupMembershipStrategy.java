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
import java.util.Set;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * This strategy is rumoured to work for Active Directory!
 * @since 1.10
 */
public class FromUserRecordLDAPGroupMembershipStrategy extends LDAPGroupMembershipStrategy {

    private static final Logger LOGGER = Logger.getLogger(FromUserRecordLDAPGroupMembershipStrategy.class.getName());
    private static final String USER_SEARCH_FILTER = "({0}={1})";
    private final String attributeName;

    @DataBoundConstructor
    public FromUserRecordLDAPGroupMembershipStrategy(String attributeName) {
        this.attributeName = attributeName;
    }

    public String getAttributeName() {
        return StringUtils.defaultIfEmpty(attributeName, "memberOf");
    }

    @Override
    public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username) {
        List<GrantedAuthority> result = new ArrayList<GrantedAuthority>();
        Attributes attributes = userData.getAttributes();
        final String attributeName = getAttributeName();
        Attribute attribute = attributes == null ? null : attributes.get(attributeName);
        if (attribute != null) {
            try {
                for (Object value: Collections.list(attribute.getAll())) {
                    String groupName = String.valueOf(value);
                    try {
                        LdapName dn = new LdapName(groupName);
                        groupName = String.valueOf(dn.getRdn(dn.size() - 1).getValue());
                    } catch (InvalidNameException e) {
                        LOGGER.log(Level.FINEST, "Expected a Group DN but found: {0}", groupName);
                    }
                    result.add(new SimpleGrantedAuthority(groupName));
                }
            } catch (NamingException e) {
                LogRecord lr = new LogRecord(Level.FINE,
                        "Failed to retrieve member of attribute ({0}) from LDAP user details");
                lr.setThrown(e);
                lr.setParameters(new Object[]{attributeName});
                LOGGER.log(lr);
            }

        }
        if (getAuthoritiesPopulator() instanceof LDAPSecurityRealm.AuthoritiesPopulatorImpl) {
            // HACK HACK HACK HACK
            LDAPSecurityRealm.AuthoritiesPopulatorImpl authoritiesPopulatorImpl =
                    (LDAPSecurityRealm.AuthoritiesPopulatorImpl) getAuthoritiesPopulator();
            if (authoritiesPopulatorImpl.isGeneratingPrefixRoles()) {
                for (GrantedAuthority ga : new ArrayList<>(result)) {
                    String role = ga.getAuthority();

                    // backward compatible name mangling
                    if (authoritiesPopulatorImpl._isConvertToUpperCase()) {
                        role = role.toUpperCase();
                    }
                    GrantedAuthority extraAuthority = new SimpleGrantedAuthority(
                            authoritiesPopulatorImpl._getRolePrefix() + role);
                    result.add(extraAuthority);
                }
            }
            result.addAll(authoritiesPopulatorImpl.getAdditionalRoles(userData, username));
            GrantedAuthority defaultRole = authoritiesPopulatorImpl.getDefaultRole();
            if (defaultRole != null) {
                result.add(defaultRole);
            }
        }

        return result;
    }

    @Override
    public Set<String> getGroupMembers(String groupDn, LDAPConfiguration conf) {
        LDAPExtendedTemplate template = conf.getLdapTemplate();
        String searchBase = conf.getUserSearchBase() != null ? conf.getUserSearchBase() : "";
        String[] filterArgs = { getAttributeName(), groupDn };
        return new HashSet<>(template.searchForAllEntries(searchBase, USER_SEARCH_FILTER,
                filterArgs, new String[]{}, new UserRecordMapper()));
    }

    /**
     * Maps users records to names.
     */
    private static class UserRecordMapper implements LdapEntryMapper<String> {
        @Override
        public String mapAttributes(String dn, Attributes attributes) throws NamingException {
            LdapName name = new LdapName(dn);
            return String.valueOf(name.getRdn(name.size() - 1).getValue());
        }
    }

    @Extension
    public static class DescriptorImpl extends LDAPGroupMembershipStrategyDescriptor {

        @Override
        public String getDisplayName() {
            return Messages.FromUserRecordLDAPGroupMembershipStrategy_DisplayName();
        }
    }
}
