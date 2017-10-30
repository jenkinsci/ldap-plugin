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

import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapCallback;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.ldap.LdapEntryMapper;
import org.acegisecurity.ldap.LdapTemplate;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.springframework.dao.DataAccessException;

@Restricted(NoExternalUse.class)
public class LDAPExtendedTemplate extends LdapTemplate {

    public LDAPExtendedTemplate(InitialDirContextFactory dirContextFactory) {
        super(dirContextFactory);
    }

    /**
     * Performs a search using the specified filter and returns the first matching entry using the
     * given {@link LdapEntryMapper} to convert the entry into a result.
     *
     * @param base the DN to search in.
     * @param filter the search filter to use.
     * @param params the parameters to substitute in the search filter.
     * @param attributeNames the attributes whose values will be retrieved. Passing null returns all attributes.
     * @param mapper the {@link LdapEntryMapper} that will convert the search results into returned values.
     *
     * @return the first matching entry converted using the specified {@link LdapEntryMapper}.
     *
     * @see LdapTemplate#searchForSingleEntry
     */
    public Object searchForFirstEntry(final String base, final String filter, final Object[] params,
            final String[] attributeNames, final LdapEntryMapper mapper) throws DataAccessException {
        try (SearchResultEnumeration searchEnum = searchForAllEntriesEnum(base, filter, params, attributeNames, mapper)) {
            return searchEnum.next();
        } catch (NamingException e) {
            throw new LdapDataAccessException("Unable to get first element", e);
        }
    }

    /**
     * Performs a search using the specified filter and returns a List of all matching entries
     * using the given {@link LdapEntryMapper} to convert each entry into a result.
     *
     * @param base the DN to search in.
     * @param filter the search filter to use.
     * @param params the parameters to substitute in the search filter.
     * @param attributeNames the attributes whose values will be retrieved. Passing null returns all attributes.
     * @param mapper the {@link LdapEntryMapper} that will convert the search results into returned values.
     *
     * @return a List of matching entries converted using the specified {@link LdapEntryMapper}.
     *
     * @see LdapTemplate#searchForSingleEntry
     */
    public @Nonnull List<? extends Object> searchForAllEntries(final String base, final String filter,
            final Object[] params, final String[] attributeNames, final LdapEntryMapper mapper)
            throws DataAccessException {
        List<Object> results = new ArrayList<>();
        try (SearchResultEnumeration searchEnum = searchForAllEntriesEnum(base, filter, params, attributeNames, mapper)) {
            while (searchEnum.hasMore()) {
                results.add(searchEnum.next());
            }
        } catch (NamingException e) {
            throw new LdapDataAccessException("Error processing search results", e);
        }
        return results;
    }

    private @Nonnull SearchResultEnumeration searchForAllEntriesEnum(final String base,
            final String filter, final Object[] params, final String[] attributeNames, final LdapEntryMapper mapper)
            throws DataAccessException {
        return (SearchResultEnumeration)execute(new LdapCallback() {
            @Override
            public SearchResultEnumeration doInDirContext(DirContext ctx) throws NamingException {
                SearchControls controls = new SearchControls();
                controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                controls.setReturningAttributes(attributeNames);
                NamingEnumeration searchResults = ctx.search(base, filter, params, controls);
                return new SearchResultEnumeration(searchResults, base, ctx.getNameInNamespace(), mapper);
            }
        });
    }

    private static final class SearchResultEnumeration implements AutoCloseable, NamingEnumeration {

        private final NamingEnumeration searchResults;
        private final String base;
        private final String nameInNamespace;
        private final LdapEntryMapper mapper;

        public SearchResultEnumeration(NamingEnumeration searchResults, String base, String nameInNamespace, LdapEntryMapper mapper) {
            this.searchResults = searchResults;
            this.base = base;
            this.nameInNamespace = nameInNamespace;
            this.mapper = mapper;
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
            // Work out the DN of the matched entry
            StringBuilder dn = new StringBuilder(searchResult.getName());

            if (base.length() > 0) {
                dn.append(",");
                dn.append(base);
            }

            if (org.springframework.util.StringUtils.hasLength(nameInNamespace)) {
                dn.append(",");
                dn.append(nameInNamespace);
            }

            return mapper.mapAttributes(dn.toString(), searchResult.getAttributes());
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
