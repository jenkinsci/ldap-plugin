package jenkins.security.plugins.ldap;

import edu.umd.cs.findbugs.annotations.NonNull;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapUserSearch;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsMapper;

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
        LdapUserDetailsImpl.Essence builder = (LdapUserDetailsImpl.Essence) template.searchForSingleEntry(
                searchBase, searchFilter, new Object[]{username}, new LdapUserDetailsMapper());
        return builder.setUsername(username).createUserDetails();
    }
}
