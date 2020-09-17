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

import hudson.model.AbstractDescribableImpl;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

import java.util.Collection;
import java.util.Set;

/**
 * A strategy for determining the groups that a user belongs to.
 *
 * @since 1.10
 */
public abstract class LDAPGroupMembershipStrategy extends AbstractDescribableImpl<LDAPGroupMembershipStrategy> {
    /**
     * The standard group member of searcher.
     */
    private transient LdapAuthoritiesPopulator authoritiesPopulator;

    /**
     * The {@link LdapAuthoritiesPopulator} to use if performing a traditional search.
     *
     * @return The {@link LdapAuthoritiesPopulator} to use if performing a traditional search.
     */
    public LdapAuthoritiesPopulator getAuthoritiesPopulator() {
        return authoritiesPopulator;
    }

    /**
     * Override this method if you want to change the configuration of the {@link LdapAuthoritiesPopulator}.
     *
     * @param authoritiesPopulator the {@link LdapAuthoritiesPopulator} to use (and abuse).
     */
    public void setAuthoritiesPopulator(LdapAuthoritiesPopulator authoritiesPopulator) {
        this.authoritiesPopulator = authoritiesPopulator;
    }

    /**
     * Returns the {@link GrantedAuthority}s that the specified user belongs to.
     *
     * @param userData as in 
     * @return the {@link GrantedAuthority}s that the specified user belongs to.
     */
    public abstract Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username);

    /**
     * Returns a {@link Set} of all members in the specified group.
     *
     * @param groupDn the DN of the group whose members will be returned.
     * @param conf the {@link LDAPConfiguration} that controls some search variables.
     *
     * @return a set of all members in the specified group, or null if the members could not be found.
     * @since 1.18
     */
    public Set<String> getGroupMembers(String groupDn, LDAPConfiguration conf) {
        return null;
    }
}
