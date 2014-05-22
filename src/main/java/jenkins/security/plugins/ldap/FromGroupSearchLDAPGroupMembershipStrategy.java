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
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Traditional strategy.
 * @since 1.10
 */
public class FromGroupSearchLDAPGroupMembershipStrategy extends LDAPGroupMembershipStrategy {

    /**
     * The search filter to apply to groups. Only those groups matching this criteria will be considered as groups
     * that the user belongs to.
     *
     * Note: we leave the default blank in case legacy users have customized their {@code LDAPBindSecurityRealm.groovy}
     * as prior to 1.5 that was the only way to change the group membership filter.
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
    public GrantedAuthority[] getGrantedAuthorities(LdapUserDetails ldapUser) {
        return getAuthoritiesPopulator().getGrantedAuthorities(ldapUser);
    }

    @Extension
    public static class DescriptorImpl extends LDAPGroupMembershipStrategyDescriptor {

        @Override
        public String getDisplayName() {
            return Messages.FromGroupSearchLDAPGroupMembershipStrategy_DisplayName();
        }
    }
}
