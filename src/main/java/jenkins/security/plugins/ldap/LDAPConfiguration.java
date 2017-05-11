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

import groovy.lang.Binding;
import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.security.LDAPSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import hudson.util.Secret;
import hudson.util.spring.BeanBuilder;
import jenkins.model.Jenkins;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapTemplate;
import org.acegisecurity.ldap.search.FilterBasedLdapUserSearch;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.apache.commons.io.input.AutoCloseInputStream;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.Nonnull;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static hudson.Util.fixEmpty;
import static hudson.Util.fixEmptyAndTrim;
import static hudson.Util.fixNull;

/**
 * A configuration for one ldap connection
 */
public class LDAPConfiguration extends AbstractDescribableImpl<LDAPConfiguration> {

    private static final Logger LOGGER = LDAPSecurityRealm.LOGGER;
    @Restricted(NoExternalUse.class)
    public static final String SECURITY_REALM_LDAPBIND_GROOVY = "LDAPBindSecurityRealm.groovy";

    /**
     * LDAP server name(s) separated by spaces, optionally with TCP port number, like "ldap.acme.org"
     * or "ldap.acme.org:389" and/or with protcol, like "ldap://ldap.acme.org".
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
    private Map<String,String> extraEnvVars;
    /**
     * Set in {@link #createApplicationContext(LDAPSecurityRealm, boolean)}
     */
    private transient LdapTemplate ldapTemplate;

    @DataBoundConstructor
    public LDAPConfiguration(@Nonnull String server, String rootDN, boolean inhibitInferRootDN, String managerDN, Secret managerPasswordSecret) {
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
     * or "ldap.acme.org:389" and/or with protcol, like "ldap://ldap.acme.org".
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

        public boolean noCustomBindScript() {
            return !getLdapBindOverrideFile(Jenkins.getActiveInstance()).exists();
        }

        // note that this works better in 1.528+ (JENKINS-19124)
        public FormValidation doCheckServer(@QueryParameter String value, @QueryParameter String managerDN, @QueryParameter Secret managerPasswordSecret) {
            String server = value;
            String managerPassword = Secret.toString(managerPasswordSecret);

            final Jenkins jenkins = Jenkins.getInstance();
            if (jenkins == null) {
                return FormValidation.error("Jenkins is not ready. Cannot validate the field");
            }
            if(!jenkins.hasPermission(Jenkins.ADMINISTER))
                return FormValidation.ok();

            try {
                Hashtable<String,String> props = new Hashtable<String,String>();
                if(managerDN!=null && managerDN.trim().length() > 0  && !"undefined".equals(managerDN)) {
                    props.put(Context.SECURITY_PRINCIPAL,managerDN);
                }
                if(managerPassword!=null && managerPassword.trim().length() > 0 && !"undefined".equals(managerPassword)) {
                    props.put(Context.SECURITY_CREDENTIALS,managerPassword);
                }
                props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                props.put(Context.PROVIDER_URL, LDAPSecurityRealm.toProviderUrl(server, ""));

                DirContext ctx = new InitialDirContext(props);
                ctx.getAttributes("");
                return FormValidation.ok();   // connected
            } catch (NamingException e) {
                // trouble-shoot
                Matcher m = Pattern.compile("(ldaps?://)?([^:]+)(?:\\:(\\d+))?(\\s+(ldaps?://)?([^:]+)(?:\\:(\\d+))?)*").matcher(server.trim());
                if(!m.matches())
                    return FormValidation.error(hudson.security.Messages.LDAPSecurityRealm_SyntaxOfServerField());

                try {
                    InetAddress adrs = InetAddress.getByName(m.group(2));
                    int port = m.group(1)!=null ? 636 : 389;
                    if(m.group(3)!=null)
                        port = Integer.parseInt(m.group(3));
                    Socket s = new Socket(adrs,port);
                    s.close();
                } catch (UnknownHostException x) {
                    return FormValidation.error(hudson.security.Messages.LDAPSecurityRealm_UnknownHost(x.getMessage()));
                } catch (IOException x) {
                    return FormValidation.error(x, hudson.security.Messages.LDAPSecurityRealm_UnableToConnect(server, x.getMessage()));
                }

                // otherwise we don't know what caused it, so fall back to the general error report
                // getMessage() alone doesn't offer enough
                return FormValidation.error(e, hudson.security.Messages.LDAPSecurityRealm_UnableToConnect(server, e));
            } catch (NumberFormatException x) {
                // The getLdapCtxInstance method throws this if it fails to parse the port number
                return FormValidation.error(hudson.security.Messages.LDAPSecurityRealm_InvalidPortNumber());
            }
        }

        public DescriptorExtensionList<LDAPGroupMembershipStrategy, Descriptor<LDAPGroupMembershipStrategy>> getGroupMembershipStrategies() {
            final Jenkins jenkins = Jenkins.getInstance();
            if (jenkins != null) {
                return jenkins.getDescriptorList(LDAPGroupMembershipStrategy.class);
            } else {
                return DescriptorExtensionList.createDescriptorList((Jenkins)null, LDAPGroupMembershipStrategy.class);
            }
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

    @Restricted(NoExternalUse.class)
    public WebApplicationContext createApplicationContext(LDAPSecurityRealm realm, boolean usePotentialUserProvidedBinding) {
        Binding binding = new Binding();
        binding.setVariable("instance", this);
        binding.setVariable("realmInstance", realm);

        final Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins has not been started, or was already shut down");
        }

        BeanBuilder builder = new BeanBuilder(jenkins.pluginManager.uberClassLoader);
        try {
            File override = getLdapBindOverrideFile(jenkins);
            if (usePotentialUserProvidedBinding && override.exists()) {
                builder.parse(new AutoCloseInputStream(new FileInputStream(override)), binding);
            } else {
                if (override.exists()) {
                    LOGGER.warning("Not loading custom " + SECURITY_REALM_LDAPBIND_GROOVY);
                }
                builder.parse(new AutoCloseInputStream(LDAPSecurityRealm.class.getResourceAsStream(SECURITY_REALM_LDAPBIND_GROOVY)), binding);
            }

        } catch (FileNotFoundException e) {
            throw new IllegalStateException("Failed to load "+ SECURITY_REALM_LDAPBIND_GROOVY, e);
        }
        WebApplicationContext appContext = builder.createApplicationContext();

        ldapTemplate = new LdapTemplate(SecurityRealm.findBean(InitialDirContextFactory.class, appContext));

        if (groupMembershipStrategy != null) {
            groupMembershipStrategy.setAuthoritiesPopulator(SecurityRealm.findBean(LdapAuthoritiesPopulator.class, appContext));
        }

        return appContext;
    }

    @Restricted(NoExternalUse.class)
    public LdapTemplate getLdapTemplate() {
        return ldapTemplate;
    }

    @Restricted(NoExternalUse.class)
    public static File getLdapBindOverrideFile(Jenkins jenkins) {
        return new File(jenkins.getRootDir(), SECURITY_REALM_LDAPBIND_GROOVY);
    }
}
