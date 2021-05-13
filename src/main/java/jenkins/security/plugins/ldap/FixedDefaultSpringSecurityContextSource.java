package jenkins.security.plugins.ldap;

import java.net.URI;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;

/* 
 * DefaultSpringSecurityContextSource with a workaround for https://github.com/spring-projects/spring-security/issues/9742
 */
public class FixedDefaultSpringSecurityContextSource extends DefaultSpringSecurityContextSource {

    // TODO remove when https://github.com/spring-projects/spring-security/issues/9742 is fixed and in our Jenkins baseline
    public FixedDefaultSpringSecurityContextSource(String providerUrl) {
        super(providerUrl);
    }

    @Override
    public void setBase(String base) {
        // base may be encoded, so lets unencode it.
        super.setBase(decode(base));
    }
    
    static String decode(String possiblyEncoded) {
        URI uri = URI.create(possiblyEncoded);
        return uri.getPath();
    }
}
