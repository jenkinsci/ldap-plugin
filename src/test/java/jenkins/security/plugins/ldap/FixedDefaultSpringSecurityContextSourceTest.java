package jenkins.security.plugins.ldap;

import org.junit.Test;
import static jenkins.security.plugins.ldap.FixedDefaultSpringSecurityContextSource.decode;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class FixedDefaultSpringSecurityContextSourceTest {

    @Test
    public void testUnencodingOfNonEncodedString() {
        assertThat(decode("wibble"), is("wibble"));
        assertThat(decode("/wibble"), is("/wibble"));
    }

    @Test
    public void testUnencodingOfSpaceEncodedString() {
        assertThat(decode("wibble%20space"), is("wibble space"));
        assertThat(decode("/wibble%20space"), is("/wibble space"));
    }

    @Test
    public void testUnencodingOfSomethignAlreadyUnEcoded() {
        assertThat(decode("wibble space"), is("wibble space"));
        assertThat(decode("/wibble space"), is("/wibble space"));
    }

}
