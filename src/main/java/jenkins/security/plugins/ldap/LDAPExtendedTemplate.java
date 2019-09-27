/*
 * The MIT License
 *
 * Copyright 2017 CloudBees, Inc.
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

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapCallback;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.ldap.LdapEntryMapper;
import org.acegisecurity.ldap.LdapTemplate;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.springframework.dao.DataAccessException;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

@Restricted(NoExternalUse.class)
public class LDAPExtendedTemplate extends LdapTemplate {

    public LDAPExtendedTemplate(InitialDirContextFactory dirContextFactory) {
        super(dirContextFactory);
    }

    /**
     * Performs a search using the specified filter and returns the first matching entry using the
     * given {@link LdapEntryMapper} to convert the entry into a result.
     *
     * @param base the DN to search in. Must not be null.
     * @param filter the search filter to use. Must not be null.
     * @param filterArgs the arguments to substitute into the search filter. Passing null is equivalent to an empty array.
     * @param attributeNames the attributes whose values will be retrieved. Passing null returns all attributes.
     * @param mapper the {@link LdapEntryMapper} that will convert the search results into returned values. Must not be null.
     *
     * @return the first matching entry converted using the specified {@link LdapEntryMapper}, or null if no matching
     * entry was found.
     *
     * @see LdapTemplate#searchForSingleEntry
     */
    public @CheckForNull Object searchForFirstEntry(@Nonnull final String base, @Nonnull final String filter,
            final Object[] filterArgs, final String[] attributeNames, @Nonnull final LdapEntryMapper mapper)
            throws DataAccessException {
        try (SearchResultEnumeration searchEnum = searchForAllEntriesEnum(base, filter, filterArgs, attributeNames, mapper)) {
            return searchEnum.hasMore() ? searchEnum.next() : null;
        } catch (NamingException e) {
            throw new LdapDataAccessException("Unable to get first element", e);
        }
    }

    /**
     * Performs a search using the specified filter and returns a List of all matching entries
     * using the given {@link LdapEntryMapper} to convert each entry into a result.
     *
     * @param base the DN to search in. Must not be null.
     * @param filter the search filter to use. Must not be null.
     * @param filterArgs the arguments to substitute into the search filter. Passing null is equivalent to an empty array.
     * @param attributeNames the attributes whose values will be retrieved. Passing null returns all attributes.
     * @param mapper the {@link LdapEntryMapper} that will convert the search results into returned values. Must not be null.
     *
     * @return a List of matching entries converted using the specified {@link LdapEntryMapper}.
     *
     * @see LdapTemplate#searchForSingleEntry
     */
    public @Nonnull List<? extends Object> searchForAllEntries(@Nonnull final String base, @Nonnull final String filter,
            final Object[] filterArgs, final String[] attributeNames, @Nonnull final LdapEntryMapper mapper)
            throws DataAccessException {
        List<Object> results = new ArrayList<>();
        try (SearchResultEnumeration searchEnum = searchForAllEntriesEnum(base, filter, filterArgs, attributeNames, mapper)) {
            while (searchEnum.hasMore()) {
                results.add(searchEnum.next());
            }
        } catch (NamingException e) {
            throw new LdapDataAccessException("Error processing search results", e);
        }
        return results;
    }

    private @Nonnull SearchResultEnumeration searchForAllEntriesEnum(@Nonnull final String base, @Nonnull final String filter,
            final Object[] params, final String[] attributeNames, @Nonnull final LdapEntryMapper mapper)
            throws DataAccessException {
        try {
            return (SearchResultEnumeration)execute(new LdapCallback() {
                @Override
                public SearchResultEnumeration doInDirContext(DirContext ctx) throws NamingException {
                    SearchControls controls = new SearchControls();
                    controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                    controls.setReturningAttributes(attributeNames);
                    NamingEnumeration searchResults = ctx.search(base, filter, params, controls);
                    return new SearchResultEnumeration(searchResults, mapper, getDnSuffix(base, ctx.getNameInNamespace()));
                }
            });
        } catch (AuthenticationException e) {
            throw new LdapDataAccessException("Failed to search LDAP", e);
        }
    }

    private String getDnSuffix(String base, String nameInNamespace) {
        StringBuilder suffix = new StringBuilder();
        if (!StringUtils.isEmpty(base)) {
            suffix.append(",").append(base);
        }
        if (!StringUtils.isEmpty(nameInNamespace)) {
            suffix.append(",").append(nameInNamespace);
        }
        return suffix.toString();
    }

    private static final class SearchResultEnumeration implements AutoCloseable, NamingEnumeration {

        private final NamingEnumeration searchResults;
        private final LdapEntryMapper mapper;
        private final String dnSuffix;

        public SearchResultEnumeration(NamingEnumeration searchResults, LdapEntryMapper mapper, String dnSuffix) {
            this.searchResults = searchResults;
            this.mapper = mapper;
            this.dnSuffix = dnSuffix;
        }

        @Override
        public void close() throws NamingException {
            searchResults.close();
        }

        @Override
        public boolean hasMore() throws NamingException {
            return searchResults.hasMore();
        }

        @Override
        public Object next() throws NamingException {
            SearchResult searchResult = (SearchResult) searchResults.next();
            return mapper.mapAttributes(searchResult.getName() + dnSuffix, searchResult.getAttributes());
        }

        @Override
        public boolean hasMoreElements() {
            try {
                return hasMore();
            } catch (NamingException e) {
                throw new LdapDataAccessException("Unable to check for more elements", e);
            }
        }

        @Override
        public Object nextElement() {
            try {
                return next();
            } catch (NamingException e) {
                throw new LdapDataAccessException("Unable to get next element", e);
            }
        }
    }

}
