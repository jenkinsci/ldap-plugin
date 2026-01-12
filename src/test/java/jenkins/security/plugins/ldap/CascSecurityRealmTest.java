package jenkins.security.plugins.ldap;

import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import io.jenkins.plugins.casc.model.CNode;
import org.junit.jupiter.api.Test;

import static io.jenkins.plugins.casc.misc.Util.getJenkinsRoot;
import static io.jenkins.plugins.casc.misc.Util.toStringFromYamlFile;
import static io.jenkins.plugins.casc.misc.Util.toYamlString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

// Based on https://github.com/jenkinsci/configuration-as-code-plugin/blob/7766b7ef6153e3e210f257d323244c1f1470a10f/integrations/src/test/java/io/jenkins/plugins/casc/LDAPSecurityRealmTest.java
@WithJenkinsConfiguredWithCode
class CascSecurityRealmTest {

    @Test
    @ConfiguredWithCode("LDAPSecurityRealmTestNoSecret.yml")
    void export_ldap_no_secret(JenkinsConfiguredWithCodeRule r) throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        CNode yourAttribute = getJenkinsRoot(context).get("securityRealm").asMapping().get("ldap");

        String exported = toYamlString(yourAttribute);

        String expected = toStringFromYamlFile(this, "LDAPSecurityRealmTestNoSecretExpected.yml");

        assertThat(exported, is(expected));
    }
}
