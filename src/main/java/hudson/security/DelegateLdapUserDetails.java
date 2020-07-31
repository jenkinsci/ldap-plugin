package hudson.security;


import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;

import javax.annotation.Nonnull;
import javax.naming.directory.Attributes;
import javax.naming.ldap.Control;
import java.io.Serializable;

/*package access for testability*/
class DelegatedLdapUserDetails implements LdapUserDetails, Serializable {

    private static final long serialVersionUID = 1L;
    private final LdapUserDetails userDetails;
    private final String configurationId;

    public DelegatedLdapUserDetails(@Nonnull LdapUserDetails userDetails, @Nonnull String configurationId) {
        this.userDetails = userDetails;
        this.configurationId = configurationId;
    }

    @Override
    public Attributes getAttributes() {
        return userDetails.getAttributes();
    }

    @Override
    public Control[] getControls() {
        return userDetails.getControls();
    }

    @Override
    public String getDn() {
        return userDetails.getDn();
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return userDetails.getAuthorities();
    }

    @Override
    public String getPassword() {
        return userDetails.getPassword();
    }

    @Override
    public String getUsername() {
        return userDetails.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return userDetails.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return userDetails.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return userDetails.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return userDetails.isEnabled();
    }

    public LdapUserDetails getUserDetails() {
        return userDetails;
    }

    public String getConfigurationId() {
        return configurationId;
    }
}
