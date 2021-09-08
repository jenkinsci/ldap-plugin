/*
 * The MIT License
 *
 * Copyright (c) 2004-2010, Sun Microsystems, Inc., Kohsuke Kawaguchi, Seiji Sogabe,
 *    Olivier Lamy
 * Copyright (c) 2017 CloudBees, Inc.
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

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.security.LDAPSecurityRealm;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import java.nio.charset.StandardCharsets;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.InitialLdapContext;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static hudson.Util.fixEmpty;
import static hudson.Util.fixEmptyAndTrim;
import static hudson.Util.fixNull;
import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * A configuration for one ldap connection
 */
public class LDAPConfiguration extends AbstractDescribableImpl<LDAPConfiguration> {

    private static final Logger LOGGER = LDAPSecurityRealm.LOGGER;

    public static final int CONNECT_TIMEOUT =
            Integer.getInteger(LDAPConfiguration.class.getName() + "connect.timeout", 30000);
    public static final int READ_TIMEOUT =
            Integer.getInteger(LDAPConfiguration.class.getName() + "read.timeout", 60000);


    /**
     * LDAP server name(s) separated by spaces, optionally with TCP port number, like "ldap.acme.org"
     * or "ldap.acme.org:389" and/or with protocol, like "ldap://ldap.acme.org".
     */
    private final String server;

    /**
     * The root DN to connect to. Normally something like "dc=sun,dc=com"
     */
    private final String rootDN;
    /**
     * Allow the rootDN to be inferred? Default is false.
     * If true, allow rootDN to be blank.
     */
    private final boolean inhibitInferRootDN;
    private String userSearchBase;
    private String userSearch;
    private String groupSearchBase;
    private String groupSearchFilter;
    private LDAPGroupMembershipStrategy groupMembershipStrategy;
    /**
     * If non-null, we use this and {@link #getManagerPassword()}
     * when binding to LDAP.
     *
     * This is necessary when LDAP doesn't support anonymous access.
     */
    private final String managerDN;
    /**
     * Password used to first bind to LDAP.
     */
    private final Secret managerPasswordSecret;
    private String displayNameAttributeName;
    private String mailAddressAttributeName;
    /**
     * If true, then any operation using this configuration which fails to connect to the server will try
     * again using the next configuration. This could be a security issue if the same username exists in
     * multiple LDAP configurations but should not correspond to the same Jenkins user, so it defaults to false.
     */
    private boolean ignoreIfUnavailable;
    private Map<String,String> extraEnvVars;
    /**
     * Set in {@link #createApplicationContext(LDAPSecurityRealm)}
     */
    private transient LDAPExtendedTemplate ldapTemplate;
    private transient String id;

    @DataBoundConstructor
    public LDAPConfiguration(@NonNull String server, String rootDN, boolean inhibitInferRootDN, String managerDN, Secret managerPasswordSecret) {
        this.server = server.trim();
        this.managerDN = fixEmpty(managerDN);
        this.managerPasswordSecret = managerPasswordSecret;
        this.inhibitInferRootDN = inhibitInferRootDN;
        if (!inhibitInferRootDN && fixEmptyAndTrim(rootDN) == null) {
            rootDN = fixNull(inferRootDN(server));
        }
        this.rootDN = rootDN;
        this.displayNameAttributeName = LDAPSecurityRealm.DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME;
        this.mailAddressAttributeName = LDAPSecurityRealm.DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME;
        this.userSearchBase = "";
        this.userSearch = LDAPSecurityRealm.DescriptorImpl.DEFAULT_USER_SEARCH;
        this.groupMembershipStrategy = new FromGroupSearchLDAPGroupMembershipStrategy("");
        this.groupSearchBase = "";
    }

    /**
     * LDAP server name(s) separated by spaces, optionally with TCP port number, like "ldap.acme.org"
     * or "ldap.acme.org:389" and/or with protocol, like "ldap://ldap.acme.org".
     */
    public String getServer() {
        return server;
    }

    public String getServerUrl() {
        StringBuilder buf = new StringBuilder();
        boolean first = true;
        for (String s : Util.fixNull(server).split("\\s+")) {
            if (s.trim().length() == 0) continue;
            if (first) first = false;
            else buf.append(' ');
            buf.append(addPrefix(s));
        }
        return buf.toString();
    }

    /**
     * The root DN to connect to. Normally something like "dc=sun,dc=com"
     */
    public String getRootDN() {
        return rootDN;
    }

    public String getLDAPURL() {
        return LDAPSecurityRealm.toProviderUrl(getServerUrl(), fixNull(rootDN));
    }

    /**
     * Allow the rootDN to be inferred? Default is false.
     * If true, allow rootDN to be blank.
     */
    public boolean isInhibitInferRootDN() {
        return inhibitInferRootDN;
    }

    /**
     * Specifies the relative DN from {@link #rootDN the root DN}.
     * This is used to narrow down the search space when doing user search.
     *
     * Something like "ou=people" but can be empty.
     */
    public String getUserSearchBase() {
        return userSearchBase;
    }

    /**
     * Specifies the relative DN from {@link #rootDN the root DN}.
     * This is used to narrow down the search space when doing user search.
     *
     * Something like "ou=people" but can be empty.
     */
    @DataBoundSetter
    public void setUserSearchBase(String userSearchBase) {
        this.userSearchBase = fixNull(userSearchBase).trim();
    }

    /**
     * Query to locate an entry that identifies the user, given the user name string.
     *
     * Normally "uid={0}"
     *
     * @see FilterBasedLdapUserSearch
     */
    public String getUserSearch() {
        return userSearch;
    }

    /**
     * Query to locate an entry that identifies the user, given the user name string.
     *
     * Normally "uid={0}"
     *
     * @see FilterBasedLdapUserSearch
     */
    @DataBoundSetter
    public void setUserSearch(String userSearch) {
        userSearch = fixEmptyAndTrim(userSearch);
        this.userSearch = userSearch != null ? userSearch : LDAPSecurityRealm.DescriptorImpl.DEFAULT_USER_SEARCH;
    }

    /**
     * This defines the organizational unit that contains groups.
     *
     * Normally "" to indicate the full LDAP search, but can be often narrowed down to
     * something like "ou=groups"
     *
     * @see FilterBasedLdapUserSearch
     */
    public String getGroupSearchBase() {
        return groupSearchBase;
    }

    /**
     * This defines the organizational unit that contains groups.
     *
     * Normally "" to indicate the full LDAP search, but can be often narrowed down to
     * something like "ou=groups"
     *
     * @see FilterBasedLdapUserSearch
     */
    @DataBoundSetter
    public void setGroupSearchBase(String groupSearchBase) {
        this.groupSearchBase = fixEmptyAndTrim(groupSearchBase);
    }

    /**
     * Query to locate an entry that identifies the group, given the group name string. If non-null it will override
     * the default specified by {@link LDAPSecurityRealm#GROUP_SEARCH}
     *
     */
    public String getGroupSearchFilter() {
        return groupSearchFilter;
    }

    /**
     * Query to locate an entry that identifies the group, given the group name string. If non-null it will override
     * the default specified by {@link LDAPSecurityRealm#GROUP_SEARCH}
     *
     */
    @DataBoundSetter
    public void setGroupSearchFilter(String groupSearchFilter) {
        this.groupSearchFilter = fixEmptyAndTrim(groupSearchFilter);
    }

    public LDAPGroupMembershipStrategy getGroupMembershipStrategy() {
        return groupMembershipStrategy;
    }

    @DataBoundSetter
    public void setGroupMembershipStrategy(LDAPGroupMembershipStrategy groupMembershipStrategy) {
        this.groupMembershipStrategy = groupMembershipStrategy == null ? new FromGroupSearchLDAPGroupMembershipStrategy("") : groupMembershipStrategy;
    }

    /**
     * If non-null, we use this and {@link #getManagerPassword()}
     * when binding to LDAP.
     *
     * This is necessary when LDAP doesn't support anonymous access.
     */
    public String getManagerDN() {
        return managerDN;
    }

    /**
     * Password used to first bind to LDAP.
     */
    public String getManagerPassword() {
        return Secret.toString(managerPasswordSecret);
    }

    public Secret getManagerPasswordSecret() {
        return managerPasswordSecret;
    }

    public String getDisplayNameAttributeName() {
        return StringUtils.defaultString(displayNameAttributeName, LDAPSecurityRealm.DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME);
    }

    @DataBoundSetter
    public void setDisplayNameAttributeName(String displayNameAttributeName) {
        this.displayNameAttributeName = displayNameAttributeName;
    }

    public String getMailAddressAttributeName() {
        return StringUtils.defaultString(mailAddressAttributeName, LDAPSecurityRealm.DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME);
    }

    @DataBoundSetter
    public void setMailAddressAttributeName(String mailAddressAttributeName) {
        this.mailAddressAttributeName = mailAddressAttributeName;
    }

    public boolean isIgnoreIfUnavailable() {
        return ignoreIfUnavailable;
    }

    @DataBoundSetter
    public void setIgnoreIfUnavailable(boolean ignoreIfUnavailable) {
        this.ignoreIfUnavailable = ignoreIfUnavailable;
    }

    public Map<String,String> getExtraEnvVars() {
        return extraEnvVars == null || extraEnvVars.isEmpty()
                ? Collections.<String,String>emptyMap()
                : Collections.unmodifiableMap(extraEnvVars);
    }

    @Restricted(NoExternalUse.class) //Only for migration
    public void setExtraEnvVars(Map<String,String> extraEnvVars) {
        this.extraEnvVars = extraEnvVars;
    }

    public LDAPSecurityRealm.EnvironmentProperty[] getEnvironmentProperties() {
        if (extraEnvVars == null || extraEnvVars.isEmpty()) {
            return new LDAPSecurityRealm.EnvironmentProperty[0];
        }
        LDAPSecurityRealm.EnvironmentProperty[] result = new LDAPSecurityRealm.EnvironmentProperty[extraEnvVars.size()];
        int i = 0;
        for (Map.Entry<String,String> entry: extraEnvVars.entrySet()) {
            result[i++] = new LDAPSecurityRealm.EnvironmentProperty(entry.getKey(), entry.getValue());
        }
        return result;
    }

    @DataBoundSetter
    public void setEnvironmentProperties(LDAPSecurityRealm.EnvironmentProperty[] environmentProperties) {
        this.extraEnvVars = environmentProperties == null || environmentProperties.length == 0
                ? null
                : LDAPSecurityRealm.EnvironmentProperty.toMap(Arrays.asList(environmentProperties));
    }

    public String getId() {
        if (StringUtils.isEmpty(this.id)) {
            this.id = generateId();
        }
        return this.id;
    }

    public boolean isConfiguration(String id) {
        return getId().equals(id);
    }

    @Extension
    public static final class LDAPConfigurationDescriptor extends Descriptor<LDAPConfiguration> {
        //For jelly usage
        public static final String DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME = LDAPSecurityRealm.DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME;
        public static final String DEFAULT_MAILADDRESS_ATTRIBUTE_NAME = LDAPSecurityRealm.DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME;
        public static final String DEFAULT_USER_SEARCH = LDAPSecurityRealm.DescriptorImpl.DEFAULT_USER_SEARCH;

        @Override
        public String getDisplayName() {
            return "ldap";
        }

        public FormValidation doCheckServer(@QueryParameter String value, @QueryParameter String managerDN, @QueryParameter Secret managerPasswordSecret,@QueryParameter String rootDN) {
            String server = value;
            String managerPassword = Secret.toString(managerPasswordSecret);

            if(!Jenkins.get().hasPermission(Jenkins.ADMINISTER))
                return FormValidation.ok();

            Context ctx = null;
            try {
                Hashtable<String,Object> props = new Hashtable<>();
                if(StringUtils.isNotBlank(managerDN)  && !"undefined".equals(managerDN)) {
                    props.put(Context.SECURITY_PRINCIPAL,managerDN);
                }
                if(StringUtils.isNotBlank(managerPassword) && !"undefined".equals(managerPassword)) {
                    props.put(Context.SECURITY_CREDENTIALS,managerPassword);
                }
                // normal
                props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                props.put(Context.PROVIDER_URL, LDAPSecurityRealm.toProviderUrl(server,rootDN));

                props.put("java.naming.referral", "follow");
                props.put("com.sun.jndi.ldap.connect.timeout", Integer.toString(CONNECT_TIMEOUT));
                props.put("com.sun.jndi.ldap.connect.pool", "true");
                props.put("com.sun.jndi.ldap.read.timeout", Integer.toString(READ_TIMEOUT));

                ctx = new InitialDirContext(props);
                return FormValidation.ok();   // connected
            } catch (NamingException e) {
                // trouble-shoot
                Matcher m = Pattern.compile("(ldaps?://)?([^:]+)(?:\\:(\\d+))?(\\s+(ldaps?://)?([^:]+)(?:\\:(\\d+))?)*").matcher(server.trim());
                if(!m.matches())
                    return FormValidation.error(Messages.LDAPSecurityRealm_SyntaxOfServerField());

                try {
                    InetAddress address = InetAddress.getByName(m.group(2));
                    int port = m.group(1)!=null ? 636 : 389;
                    if(m.group(3)!=null)
                        port = Integer.parseInt(m.group(3));
                    Socket s = new Socket(address,port);
                    s.close();
                } catch (UnknownHostException x) {
                    return FormValidation.error(Messages.LDAPSecurityRealm_UnknownHost(x.getMessage()));
                } catch (IOException x) {
                    return FormValidation.error(x, Messages.LDAPSecurityRealm_UnableToConnect(server, x.getMessage()));
                }

                // otherwise we don't know what caused it, so fall back to the general error report
                // getMessage() alone doesn't offer enough
                return FormValidation.error(e, Messages.LDAPSecurityRealm_UnableToConnect(server, e));
            } catch (NumberFormatException x) {
                // The getLdapCtxInstance method throws this if it fails to parse the port number
                return FormValidation.error(Messages.LDAPSecurityRealm_InvalidPortNumber());
            } finally {
                forceClose(ctx);
            }
        }

        private void forceClose(Context ctx){
            if(ctx==null){
                return;
            }
            try {
                ctx.close();
            } catch (Exception e) {
                LOGGER.log(Level.FINE, "fail to close ldap context", e);
            }
        }

        public DescriptorExtensionList<LDAPGroupMembershipStrategy, Descriptor<LDAPGroupMembershipStrategy>> getGroupMembershipStrategies() {
            return Jenkins.get().getDescriptorList(LDAPGroupMembershipStrategy.class);
        }
    }

    /**
     * Infer the root DN.
     *
     * @return null if not found.
     */
    private String inferRootDN(String server) {
        try {
            Hashtable<String, String> props = new Hashtable<String, String>();
            if (managerDN != null) {
                props.put(Context.SECURITY_PRINCIPAL, managerDN);
                props.put(Context.SECURITY_CREDENTIALS, getManagerPassword());
            }
            props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            props.put(Context.PROVIDER_URL, LDAPSecurityRealm.toProviderUrl(getServerUrl(), ""));

            DirContext ctx = new InitialDirContext(props);
            Attributes atts = ctx.getAttributes("");
            Attribute a = atts.get("defaultNamingContext");
            if (a != null && a.get() != null) // this entry is available on Active Directory. See http://msdn2.microsoft.com/en-us/library/ms684291(VS.85).aspx
                return a.get().toString();

            a = atts.get("namingcontexts");
            if (a == null) {
                LOGGER.warning("namingcontexts attribute not found in root DSE of " + server);
                return null;
            }
            return a.get().toString();
        } catch (NamingException e) {
            LOGGER.log(Level.WARNING, "Failed to connect to LDAP to infer Root DN for " + server, e);
            return null;
        }
    }

    /**
     * If the given "server name" is just a host name (plus optional host name), add ldap:// prefix.
     * Otherwise assume it already contains the scheme, and leave it intact.
     */
    private static String addPrefix(String server) {
        if (server.contains("://")) return server;
        else return "ldap://" + server;
    }

    private String generateId() {
        return generateId(server, rootDN, userSearchBase, userSearch);
    }

    @Restricted(NoExternalUse.class)
    static String generateId(String serverUrl, String rootDN, String userSearchBase, String userSearch) {
        final MessageDigest digest = DigestUtils.getMd5Digest();
        digest.update(normalizeServer(serverUrl).getBytes(StandardCharsets.UTF_8));
        String userSearchBaseNormalized = normalizeUserSearchBase(rootDN, userSearchBase);
        if (isNotBlank(userSearchBaseNormalized)) {
            digest.update(userSearchBaseNormalized.getBytes(StandardCharsets.UTF_8));
        } else {
            digest.update(new byte[]{0});
        }
        if (isNotBlank(userSearch)) {
            digest.update(userSearch.getBytes(StandardCharsets.UTF_8));
        } else {
            digest.update(LDAPConfigurationDescriptor.DEFAULT_USER_SEARCH.getBytes(StandardCharsets.UTF_8));
        }
        return Base64.encodeBase64String(digest.digest());
    }

    private static String normalizeUserSearchBase(String rootDN, String userSearchBase) {
        if (isBlank(rootDN) && isBlank(userSearchBase)) {
            return "";
        }
        if (isBlank(rootDN)) {
            return userSearchBase;
        }
        if (isBlank(userSearchBase)) {
            return rootDN;
        }
        rootDN = rootDN.trim();
        userSearchBase = userSearchBase.trim();
        return userSearchBase + "," + rootDN;
    }

    @Restricted(NoExternalUse.class)
    static String normalizeServer(String server) { /*package scope for testing*/
        String[] urls = Util.fixNull(server).split("\\s+");
        List<String> normalised = new ArrayList<>(urls.length);
        for (String url : urls) {
            if (isBlank(url)) {
                continue;
            }
            url = addPrefix(url);
            try {
                URI uri = new URI(url);
                if (uri.getPort() < 0) {
                    uri = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), 389, uri.getPath(), uri.getQuery(), uri.getFragment());
                }
                normalised.add(uri.toString());
            } catch (URISyntaxException e) {
                LOGGER.warning("Unable to parse " + url + " into an URI");
            }
        }
        Collections.sort(normalised);
        return StringUtils.join(normalised, ' ');
    }

    public static final class ApplicationContext {
        public final AuthenticationManager authenticationManager;
        public final LdapUserSearch ldapUserSearch;
        public final LdapAuthoritiesPopulator ldapAuthoritiesPopulator;
        ApplicationContext(AuthenticationManager authenticationManager, LdapUserSearch ldapUserSearch, LdapAuthoritiesPopulator ldapAuthoritiesPopulator) {
            this.authenticationManager = authenticationManager;
            this.ldapUserSearch = ldapUserSearch;
            this.ldapAuthoritiesPopulator = ldapAuthoritiesPopulator;
        }
    }

    @Restricted(NoExternalUse.class)
    public ApplicationContext createApplicationContext(LDAPSecurityRealm realm) {
        // https://issues.jenkins.io/browse/JENKINS-65628 / https://github.com/spring-projects/spring-security/issues/9742
        DefaultSpringSecurityContextSource contextSource = new FixedDefaultSpringSecurityContextSource(getLDAPURL());
        if (getManagerDN() != null) {
            contextSource.setUserDn(getManagerDN());
            contextSource.setPassword(getManagerPassword());
        }
        contextSource.setReferral("follow");
        Map<String, Object> vars = new HashMap<>();
        vars.put("com.sun.jndi.ldap.connect.pool", "true");
        vars.put("com.sun.jndi.ldap.connect.timeout", Integer.toString(CONNECT_TIMEOUT)); // timeout if no connection after 30 seconds
        vars.put("com.sun.jndi.ldap.read.timeout", Integer.toString(READ_TIMEOUT)); // timeout if no response after 60 seconds
        vars.putAll(getExtraEnvVars());
        contextSource.setBaseEnvironmentProperties(vars);
        contextSource.afterPropertiesSet();

        FilterBasedLdapUserSearch ldapUserSearch = new FilterBasedLdapUserSearch(getUserSearchBase(), getUserSearch(), contextSource);
        ldapUserSearch.setSearchSubtree(true);
        // enable operational attributes (+) along with normal attributes (*)
        ldapUserSearch.setReturningAttributes(new String[]{"*", "+"});

        BindAuthenticator2 bindAuthenticator = new BindAuthenticator2(contextSource);
        // this is when you the user name can be translated into DN.
        // bindAuthenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});
        // this is when we need to find it.
        bindAuthenticator.setUserSearch(ldapUserSearch);

        LDAPSecurityRealm.AuthoritiesPopulatorImpl ldapAuthoritiesPopulator = new LDAPSecurityRealm.AuthoritiesPopulatorImpl(contextSource, getGroupSearchBase());
        ldapAuthoritiesPopulator.setSearchSubtree(true);
        ldapAuthoritiesPopulator.setGroupSearchFilter("(| (member={0}) (uniqueMember={0}) (memberUid={1}))");
        if (realm.isDisableRolePrefixing()) {
            ldapAuthoritiesPopulator.setRolePrefix("");
            ldapAuthoritiesPopulator.setConvertToUpperCase(false);
        }

        List<AuthenticationProvider> providers = new ArrayList<>();
        // talk to LDAP
        providers.add(new LDAPSecurityRealm.LdapAuthenticationProviderImpl(bindAuthenticator, ldapAuthoritiesPopulator, getGroupMembershipStrategy()));
        // these providers apply everywhere
        providers.add(new RememberMeAuthenticationProvider(Jenkins.get().getSecretKey()));
        // this doesn't mean we allow anonymous access.
        // we just authenticate anonymous users as such,
        // so that later authorization can reject them if so configured
        providers.add(new AnonymousAuthenticationProvider("anonymous"));
        ProviderManager authenticationManager = new ProviderManager(providers);

        ldapTemplate = new LDAPExtendedTemplate(contextSource);

        if (groupMembershipStrategy != null) {
            groupMembershipStrategy.setAuthoritiesPopulator(ldapAuthoritiesPopulator);
        }

        return new ApplicationContext(authenticationManager, ldapUserSearch, ldapAuthoritiesPopulator);
    }

    @Restricted(NoExternalUse.class)
    public LDAPExtendedTemplate getLdapTemplate() {
        return ldapTemplate;
    }

}
