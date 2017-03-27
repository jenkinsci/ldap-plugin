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
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import java.util.ArrayList;
import java.util.Collections;
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
    private final String attributeName;

    @DataBoundConstructor
    public FromUserRecordLDAPGroupMembershipStrategy(String attributeName) {
        this.attributeName = attributeName;
    }

    public String getAttributeName() {
        return StringUtils.defaultIfEmpty(attributeName, "memberOf");
    }

    @Override
    public GrantedAuthority[] getGrantedAuthorities(LdapUserDetails ldapUser) {
        List<GrantedAuthority> result = new ArrayList<GrantedAuthority>();
        Attributes attributes = ldapUser.getAttributes();
        final String attributeName = getAttributeName();

        LOGGER.log(Level.FINEST, "Looking for groupmembership at {0} attribute", attributeName);

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
                    result.add(new GrantedAuthorityImpl(groupName));
                }
            } catch (NamingException e) {
                LogRecord lr = new LogRecord(Level.FINE,
                        "Failed to retrieve member of attribute ({0}) from LDAP user details");
                lr.setThrown(e);
                lr.setParameters(new Object[]{attributeName});
                LOGGER.log(lr);
            }

        }
        return result.toArray(new GrantedAuthority[result.size()]);
    }

    @Extension
    public static class DescriptorImpl extends LDAPGroupMembershipStrategyDescriptor {

        @Override
        public String getDisplayName() {
            return Messages.FromUserRecordLDAPGroupMembershipStrategy_DisplayName();
        }
    }
}