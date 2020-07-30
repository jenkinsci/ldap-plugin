package jenkins.security.plugins.ldap;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.security.ACL;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Logger;

final class CredentialsMigrator {

    private CredentialsMigrator() {}

    private static final Logger LOGGER = Logger.getLogger(CredentialsMigrator.class.getName());

    static Optional<StandardCredentials> migrate(String managerDN, Secret managerPasswordSecret) {
        if(StringUtils.isBlank(managerDN)) {
            return Optional.empty();
        }
        LOGGER.info("Migrating LDAP credentials: Moving manager DN and password into the credentials store");
        List<StandardUsernamePasswordCredentials> allUsernamePasswordCredentials = CredentialsMatchers.filter(
                CredentialsProvider.lookupCredentials(
                        StandardUsernamePasswordCredentials.class,
                        Jenkins.getInstanceOrNull(),
                        ACL.SYSTEM,
                        (DomainRequirement) null),
                CredentialsMatchers.always());

        return Optional.of(allUsernamePasswordCredentials
                .stream()
                .filter(cred -> cred.getUsername().equals(managerDN))
                .filter(cred -> cred.getPassword().equals(managerPasswordSecret))
                .findAny()
                .orElseGet(() -> addCredentialsIfNotPresent(managerDN, managerPasswordSecret)));
    }

    private static StandardUsernamePasswordCredentials addCredentialsIfNotPresent(@Nonnull String managerDN, @Nonnull Secret managerPassword) {
        StandardUsernamePasswordCredentials credentials = new UsernamePasswordCredentialsImpl(
                CredentialsScope.SYSTEM,
                UUID.randomUUID().toString(),
                "Migrated LDAP manager credentials",
                managerDN,
                managerPassword.getPlainText());

        SystemCredentialsProvider instance = SystemCredentialsProvider.getInstance();
        instance.getCredentials().add(credentials);
        try {
            instance.save();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return credentials;
    }
}
