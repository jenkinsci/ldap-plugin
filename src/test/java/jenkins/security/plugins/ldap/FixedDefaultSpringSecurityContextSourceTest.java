package jenkins.security.plugins.ldap;

import org.junit.jupiter.api.Test;

import static jenkins.security.plugins.ldap.FixedDefaultSpringSecurityContextSource.decode;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class FixedDefaultSpringSecurityContextSourceTest {

    @Test
    void testUnencodingOfNonEncodedString() {
        assertThat(decode("wibble"), is("wibble"));
        assertThat(decode("/wibble"), is("/wibble"));
    }

    @Test
    void testUnencodingOfSpaceEncodedString() {
        assertThat(decode("wibble%20space"), is("wibble space"));
        assertThat(decode("/wibble%20space"), is("/wibble space"));
    }

    @Test
    void testUnencodingOfSomethingAlreadyUnEncoded() {
        assertThat(decode("wibble space"), is("wibble space"));
        assertThat(decode("/wibble space"), is("/wibble space"));
    }
}
