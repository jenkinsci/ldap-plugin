package jenkins.security.plugins.ldap;

import java.net.URI;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;

/**
 * DefaultSpringSecurityContextSource with a workaround for https://github.com/spring-projects/spring-security/issues/9742
 */
public class FixedDefaultSpringSecurityContextSource extends DefaultSpringSecurityContextSource {

    private static Logger LOGGER  = Logger.getLogger(FixedDefaultSpringSecurityContextSource.class.getName());

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
        // just incase somethign already gets encoded (as it is fixed upstream) if we can not decode
        // for example "foo%20bar" was already decoded in the supers constructor before calling setBase
        // we just return the string.
        try {
            URI uri = URI.create(possiblyEncoded);
            return uri.getPath();
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.WARNING, "Failed to decode baseDN, perhaps https://github.com/spring-projects/spring-security/issues/9742 is fixed and JENKINS-65628 should be reverted", e);
            return possiblyEncoded;
        }
    }
}
