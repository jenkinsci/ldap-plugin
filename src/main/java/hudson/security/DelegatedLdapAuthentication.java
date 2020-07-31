package hudson.security;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;

/*package access for testability*/
static class DelegatedLdapAuthentication implements Authentication {
    private final Authentication delegate;
    private final String configurationId;

    public DelegatedLdapAuthentication(Authentication delegate, String configurationId) {
        this.delegate = delegate;
        this.configurationId = configurationId;
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return delegate.getAuthorities();
    }

    @Override
    public Object getCredentials() {
        return delegate.getCredentials();
    }

    @Override
    public Object getDetails() {
        return delegate.getDetails();
    }

    @Override
    public Object getPrincipal() {
        Object principal = delegate.getPrincipal();
        if (principal instanceof LdapUserDetails && !(principal instanceof LDAPSecurityRealm.DelegatedLdapUserDetails)) {
            return new LDAPSecurityRealm.DelegatedLdapUserDetails((LdapUserDetails) principal, this.configurationId);
        } else {
            return principal;
        }
    }

    @Override
    public boolean isAuthenticated() {
        return delegate.isAuthenticated();
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        delegate.setAuthenticated(isAuthenticated);
    }

    @Override
    public String getName() {
        return delegate.getName();
    }

    public Authentication getDelegate() {
        return delegate;
    }

    public String getConfigurationId() {
        return configurationId;
    }
}