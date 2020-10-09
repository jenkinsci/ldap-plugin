/*
 * The MIT License
 *
 * Copyright (c) 2020 CloudBees, Inc.
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

import edu.umd.cs.findbugs.annotations.NonNull;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapUserSearch;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsMapper;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

import javax.naming.directory.SearchControls;

public class OperationalAttributesLdapUserSearch implements LdapUserSearch {
    private final String searchBase;
    private final String searchFilter;
    private final InitialDirContextFactory factory;
    private final SearchControls searchControls = new SearchControls();

    public OperationalAttributesLdapUserSearch(@NonNull String searchBase, @NonNull String searchFilter, @NonNull InitialDirContextFactory factory) {
        this.searchBase = searchBase;
        this.searchFilter = searchFilter;
        this.factory = factory;
        // enable operational attributes (+) along with normal attributes (*)
        searchControls.setReturningAttributes(new String[]{"*", "+"});
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    }


    @Override
    public LdapUserDetails searchForUser(String username) {
        LDAPExtendedTemplate template = new LDAPExtendedTemplate(factory);
        template.setSearchControls(searchControls);
        LdapUserDetailsImpl.Essence builder;
        try {
            builder = (LdapUserDetailsImpl.Essence) template.searchForSingleEntry(
                    searchBase, searchFilter, new Object[]{username}, new LdapUserDetailsMapper());
        } catch (IncorrectResultSizeDataAccessException e) {
            if (e.getActualSize() == 0) {
                throw new UsernameNotFoundException("User " + username + " not found in LDAP");
            }
            throw e;
        }
        return builder.setUsername(username).createUserDetails();
    }
}
