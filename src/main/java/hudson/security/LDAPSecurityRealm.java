/*
 * The MIT License
 * 
 * Copyright (c) 2004-2010, Sun Microsystems, Inc., Kohsuke Kawaguchi, Seiji Sogabe,
 *    Olivier Lamy
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
package hudson.security;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import groovy.lang.Binding;
import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.tasks.MailAddressResolver;
import hudson.tasks.Mailer;
import hudson.tasks.Mailer.UserProperty;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Scrambler;
import hudson.util.Secret;
import hudson.util.spring.BeanBuilder;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import jenkins.security.plugins.ldap.FromGroupSearchLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.LDAPGroupMembershipStrategy;
import net.sf.json.JSONObject;
import org.acegisecurity.AcegiSecurityException;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.ldap.LdapTemplate;
import org.acegisecurity.ldap.LdapUserSearch;
import org.acegisecurity.ldap.search.FilterBasedLdapUserSearch;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.providers.ldap.populator.DefaultLdapAuthoritiesPopulator;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.apache.commons.collections.map.LRUMap;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.AutoCloseInputStream;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.springframework.dao.DataAccessException;
import org.springframework.web.context.WebApplicationContext;

import static hudson.Util.fixEmpty;
import static hudson.Util.fixEmptyAndTrim;
import static hudson.Util.fixNull;

/**
 * {@link SecurityRealm} implementation that uses LDAP for authentication.
 *
 *
 * <h2>Key Object Classes</h2>
 *
 * <h3>Group Membership</h3>
 *
 * <p>
 * Two object classes seem to be relevant. These are in RFC 2256 and core.schema. These use DN for membership,
 * so it can create a group of anything. I don't know what the difference between these two are.
 * <pre>
   attributetype ( 2.5.4.31 NAME 'member'
     DESC 'RFC2256: member of a group'
     SUP distinguishedName )

   attributetype ( 2.5.4.50 NAME 'uniqueMember'
     DESC 'RFC2256: unique member of a group'
     EQUALITY uniqueMemberMatch
     SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )

   objectclass ( 2.5.6.9 NAME 'groupOfNames'
     DESC 'RFC2256: a group of names (DNs)'
     SUP top STRUCTURAL
     MUST ( member $ cn )
     MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )

   objectclass ( 2.5.6.17 NAME 'groupOfUniqueNames'
     DESC 'RFC2256: a group of unique names (DN and Unique Identifier)'
     SUP top STRUCTURAL
     MUST ( uniqueMember $ cn )
     MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )
 * </pre>
 *
 * <p>
 * This one is from nis.schema, and appears to model POSIX group/user thing more closely.
 * <pre>
   objectclass ( 1.3.6.1.1.1.2.2 NAME 'posixGroup'
     DESC 'Abstraction of a group of accounts'
     SUP top STRUCTURAL
     MUST ( cn $ gidNumber )
     MAY ( userPassword $ memberUid $ description ) )

   attributetype ( 1.3.6.1.1.1.1.12 NAME 'memberUid'
     EQUALITY caseExactIA5Match
     SUBSTR caseExactIA5SubstringsMatch
     SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )

   objectclass ( 1.3.6.1.1.1.2.0 NAME 'posixAccount'
     DESC 'Abstraction of an account with POSIX attributes'
     SUP top AUXILIARY
     MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )
     MAY ( userPassword $ loginShell $ gecos $ description ) )

   attributetype ( 1.3.6.1.1.1.1.0 NAME 'uidNumber'
     DESC 'An integer uniquely identifying a user in an administrative domain'
     EQUALITY integerMatch
     SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )

   attributetype ( 1.3.6.1.1.1.1.1 NAME 'gidNumber'
     DESC 'An integer uniquely identifying a group in an administrative domain'
     EQUALITY integerMatch
     SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
 * </pre>
 *
 * <p>
 * Active Directory specific schemas (from <a href="http://www.grotan.com/ldap/microsoft.schema">here</a>).
 * <pre>
   objectclass ( 1.2.840.113556.1.5.8
     NAME 'group'
     SUP top
     STRUCTURAL
     MUST (groupType )
     MAY (member $ nTGroupMembers $ operatorCount $ adminCount $
         groupAttributes $ groupMembershipSAM $ controlAccessRights $
         desktopProfile $ nonSecurityMember $ managedBy $
         primaryGroupToken $ mail ) )

   objectclass ( 1.2.840.113556.1.5.9
     NAME 'user'
     SUP organizationalPerson
     STRUCTURAL
     MAY (userCertificate $ networkAddress $ userAccountControl $
         badPwdCount $ codePage $ homeDirectory $ homeDrive $
         badPasswordTime $ lastLogoff $ lastLogon $ dBCSPwd $
         localeID $ scriptPath $ logonHours $ logonWorkstation $
         maxStorage $ userWorkstations $ unicodePwd $
         otherLoginWorkstations $ ntPwdHistory $ pwdLastSet $
         preferredOU $ primaryGroupID $ userParameters $
         profilePath $ operatorCount $ adminCount $ accountExpires $
         lmPwdHistory $ groupMembershipSAM $ logonCount $
         controlAccessRights $ defaultClassStore $ groupsToIgnore $
         groupPriority $ desktopProfile $ dynamicLDAPServer $
         userPrincipalName $ lockoutTime $ userSharedFolder $
         userSharedFolderOther $ servicePrincipalName $
         aCSPolicyName $ terminalServer $ mSMQSignCertificates $
         mSMQDigests $ mSMQDigestsMig $ mSMQSignCertificatesMig $
         msNPAllowDialin $ msNPCallingStationID $
         msNPSavedCallingStationID $ msRADIUSCallbackNumber $
         msRADIUSFramedIPAddress $ msRADIUSFramedRoute $
         msRADIUSServiceType $ msRASSavedCallbackNumber $
         msRASSavedFramedIPAddress $ msRASSavedFramedRoute $
         mS-DS-CreatorSID ) )
 * </pre>
 *
 *
 * <h2>References</h2>
 * <dl>
 * <dt><a href="http://www.openldap.org/doc/admin22/schema.html">Standard Schemas</a>
 * <dd>
 * The downloadable distribution contains schemas that define the structure of LDAP entries.
 * Because this is a standard, we expect most LDAP servers out there to use it, although
 * there are different objectClasses that can be used for similar purposes, and apparently
 * many deployments choose to use different objectClasses.
 *
 * <dt><a href="http://www.ietf.org/rfc/rfc2256.txt">RFC 2256</a>
 * <dd>
 * Defines the meaning of several key datatypes used in the schemas with some explanations.
 *
 * <dt><a href="http://msdn.microsoft.com/en-us/library/ms675085(VS.85).aspx">Active Directory schema</a>
 * <dd>
 * More navigable schema list, including core and MS extensions specific to Active Directory.
 * </dl>
 *
 * @author Kohsuke Kawaguchi
 * @since 1.166
 */
public class LDAPSecurityRealm extends AbstractPasswordBasedSecurityRealm {
    private static final boolean FORCE_USERNAME_LOWERCASE =
            Boolean.getBoolean(LDAPSecurityRealm.class.getName() + ".forceUsernameLowercase");
    private static final boolean FORCE_GROUPNAME_LOWERCASE =
            Boolean.getBoolean(LDAPSecurityRealm.class.getName() + ".forceGroupnameLowercase");
    /**
     * LDAP server name(s) separated by spaces, optionally with TCP port number, like "ldap.acme.org"
     * or "ldap.acme.org:389" and/or with protcol, like "ldap://ldap.acme.org".
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public final String server;

    /**
     * The root DN to connect to. Normally something like "dc=sun,dc=com"
     *
     * How do I infer this?
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public final String rootDN;

    /**
     * Allow the rootDN to be inferred? Default is false.
     * If true, allow rootDN to be blank.
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public final boolean inhibitInferRootDN;

    /**
     * Specifies the relative DN from {@link #rootDN the root DN}.
     * This is used to narrow down the search space when doing user search.
     *
     * Something like "ou=people" but can be empty.
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public final String userSearchBase;

    /**
     * Query to locate an entry that identifies the user, given the user name string.
     *
     * Normally "uid={0}"
     *
     * @see FilterBasedLdapUserSearch
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public final String userSearch;

    /**
     * This defines the organizational unit that contains groups.
     *
     * Normally "" to indicate the full LDAP search, but can be often narrowed down to
     * something like "ou=groups"
     *
     * @see FilterBasedLdapUserSearch
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public final String groupSearchBase;

    /**
     * Query to locate an entry that identifies the group, given the group name string. If non-null it will override
     * the default specified by {@link #GROUP_SEARCH}
     *
     * @since 1.5
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public final String groupSearchFilter;

    /**
     * Query to locate the group entries that a user belongs to, given the user object. <code>{0}</code>
     * is the user's full DN while {1} is the username. If non-null it will override the default specified in
     * {@code LDAPBindSecurityRealm.groovy}
     *
     * @since 1.5
     * @deprecated use {@link #groupMembershipStrategy}
     */
    @Deprecated
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public transient String groupMembershipFilter;

    /**
     * @since 2.0
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public /*effectively final*/ LDAPGroupMembershipStrategy groupMembershipStrategy;

    /*
        Other configurations that are needed:

        group search base DN (relative to root DN)
        group search filter (uniquemember={1} seems like a reasonable default)
        group target (CN is a reasonable default)

        manager dn/password if anonyomus search is not allowed.

        See GF configuration at http://weblogs.java.net/blog/tchangu/archive/2007/01/ldap_security_r.html
        Geronimo configuration at http://cwiki.apache.org/GMOxDOC11/ldap-realm.html
     */

    /**
     * If non-null, we use this and {@link #managerPasswordSecret}
     * when binding to LDAP.
     *
     * This is necessary when LDAP doesn't support anonymous access.
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public final String managerDN;

    @Deprecated
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    private String managerPassword;

    /**
     * Password used to first bind to LDAP.
     */
    private Secret managerPasswordSecret;

    /**
     * Created in {@link #createSecurityComponents()}. Can be used to connect to LDAP.
     */
    private transient LdapTemplate ldapTemplate;

    /**
     * @since 1.2
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public final boolean disableMailAddressResolver;

    /**
     * The cache configuration
     * @since 1.3
     */
    private final CacheConfiguration cache;

    /**
     * The {@link UserDetails} cache.
     */
    private transient Map<String,CacheEntry<LdapUserDetails>> userDetailsCache = null;

    /**
     * The group details cache.
     */
    private transient Map<String,CacheEntry<Set<String>>> groupDetailsCache = null;

    private final Map<String,String> extraEnvVars;

    private final String displayNameAttributeName;

    private final String mailAddressAttributeName;

    private final IdStrategy userIdStrategy;

    private final IdStrategy groupIdStrategy;

    /**
     * @deprecated retained for backwards binary compatibility.
     */
    @Deprecated
    public LDAPSecurityRealm(String server, String rootDN, String userSearchBase, String userSearch, String groupSearchBase, String managerDN, String managerPassword, boolean inhibitInferRootDN) {
        this(server, rootDN, userSearchBase, userSearch, groupSearchBase, managerDN, managerPassword, inhibitInferRootDN, false);
    }

    /**
     * @deprecated retained for backwards binary compatibility.
     */
    @Deprecated
    public LDAPSecurityRealm(String server, String rootDN, String userSearchBase, String userSearch, String groupSearchBase, String managerDN, String managerPassword, boolean inhibitInferRootDN,
                             boolean disableMailAddressResolver) {
        this(server, rootDN, userSearchBase, userSearch, groupSearchBase, managerDN, managerPassword, inhibitInferRootDN,
                                     disableMailAddressResolver, null);
    }

    /**
     * @deprecated retained for backwards binary compatibility.
     */
    @Deprecated
    public LDAPSecurityRealm(String server, String rootDN, String userSearchBase, String userSearch, String groupSearchBase, String managerDN, String managerPassword, boolean inhibitInferRootDN,
                             boolean disableMailAddressResolver, CacheConfiguration cache) {
        this(server, rootDN, userSearchBase, userSearch, groupSearchBase, null, null, managerDN, managerPassword, inhibitInferRootDN, disableMailAddressResolver, cache);
    }

    /**
     * @deprecated retained for backwards binary compatibility.
     */
    @Deprecated
    public LDAPSecurityRealm(String server, String rootDN, String userSearchBase, String userSearch, String groupSearchBase, String groupSearchFilter, String groupMembershipFilter, String managerDN, String managerPassword, boolean inhibitInferRootDN, boolean disableMailAddressResolver, CacheConfiguration cache) {
        this(server, rootDN, userSearchBase, userSearch, groupSearchBase, groupSearchFilter, groupMembershipFilter, managerDN, managerPassword, inhibitInferRootDN, disableMailAddressResolver, cache, null);
    }

    /**
     * @deprecated retained for backwards binary compatibility.
     */
    @Deprecated
    public LDAPSecurityRealm(String server, String rootDN, String userSearchBase, String userSearch, String groupSearchBase, String groupSearchFilter, String groupMembershipFilter, String managerDN, String managerPassword, boolean inhibitInferRootDN, boolean disableMailAddressResolver, CacheConfiguration cache, EnvironmentProperty[] environmentProperties) {
        this(server, rootDN, userSearchBase, userSearch, groupSearchBase, groupSearchFilter, groupMembershipFilter, managerDN, managerPassword, inhibitInferRootDN, disableMailAddressResolver, cache, environmentProperties, null, null);
    }

    /**
     * @deprecated retained for backwards binary compatibility.
     */
    @Deprecated
    public LDAPSecurityRealm(String server, String rootDN, String userSearchBase, String userSearch, String groupSearchBase, String groupSearchFilter, String groupMembershipFilter, String managerDN, String managerPassword, boolean inhibitInferRootDN, boolean disableMailAddressResolver, CacheConfiguration cache, EnvironmentProperty[] environmentProperties, String displayNameAttributeName, String mailAddressAttributeName) {
        this(server, rootDN, userSearchBase, userSearch, groupSearchBase, groupSearchFilter, groupMembershipFilter, managerDN, Secret.fromString(managerPassword), inhibitInferRootDN, disableMailAddressResolver, cache, environmentProperties, null, null);
    }

    /**
     * @deprecated retained for backwards binary compatibility.
     */
    @Deprecated
    public LDAPSecurityRealm(String server, String rootDN, String userSearchBase, String userSearch, String groupSearchBase, String groupSearchFilter, String groupMembershipFilter, String managerDN, Secret managerPasswordSecret, boolean inhibitInferRootDN, boolean disableMailAddressResolver, CacheConfiguration cache, EnvironmentProperty[] environmentProperties, String displayNameAttributeName, String mailAddressAttributeName) {
        this(server, rootDN, userSearchBase, userSearch, groupSearchBase, groupSearchFilter, new FromGroupSearchLDAPGroupMembershipStrategy(groupMembershipFilter), managerDN, managerPasswordSecret, inhibitInferRootDN, disableMailAddressResolver, cache, environmentProperties, displayNameAttributeName, mailAddressAttributeName);
    }

    /**
     * @deprecated retained for backwards binary compatibility.
     */
    @Deprecated
    public LDAPSecurityRealm(String server, String rootDN, String userSearchBase, String userSearch, String groupSearchBase, String groupSearchFilter, LDAPGroupMembershipStrategy groupMembershipStrategy, String managerDN, Secret managerPasswordSecret, boolean inhibitInferRootDN, boolean disableMailAddressResolver, CacheConfiguration cache, EnvironmentProperty[] environmentProperties, String displayNameAttributeName, String mailAddressAttributeName) {
        this(server, rootDN, userSearchBase, userSearch, groupSearchBase, groupSearchFilter, groupMembershipStrategy, managerDN, managerPasswordSecret, inhibitInferRootDN, disableMailAddressResolver, cache, environmentProperties, displayNameAttributeName, mailAddressAttributeName, IdStrategy.CASE_INSENSITIVE, IdStrategy.CASE_INSENSITIVE);
    }

    @DataBoundConstructor
    public LDAPSecurityRealm(String server, String rootDN, String userSearchBase, String userSearch, String groupSearchBase, String groupSearchFilter, LDAPGroupMembershipStrategy groupMembershipStrategy, String managerDN, Secret managerPasswordSecret, boolean inhibitInferRootDN, boolean disableMailAddressResolver, CacheConfiguration cache, EnvironmentProperty[] environmentProperties, String displayNameAttributeName, String mailAddressAttributeName, IdStrategy userIdStrategy, IdStrategy groupIdStrategy) {
        this.server = server.trim();
        this.managerDN = fixEmpty(managerDN);
        this.managerPasswordSecret = managerPasswordSecret;
        this.inhibitInferRootDN = inhibitInferRootDN;
        if(!inhibitInferRootDN && fixEmptyAndTrim(rootDN)==null) rootDN= fixNull(inferRootDN(server));
        this.rootDN = rootDN.trim();
        this.userSearchBase = fixNull(userSearchBase).trim();
        userSearch = fixEmptyAndTrim(userSearch);
        this.userSearch = userSearch!=null ? userSearch : DescriptorImpl.DEFAULT_USER_SEARCH;
        this.groupSearchBase = fixEmptyAndTrim(groupSearchBase);
        this.groupSearchFilter = fixEmptyAndTrim(groupSearchFilter);
        this.groupMembershipStrategy = groupMembershipStrategy == null ? new FromGroupSearchLDAPGroupMembershipStrategy("") : groupMembershipStrategy;
        this.disableMailAddressResolver = disableMailAddressResolver;
        this.cache = cache;
        this.extraEnvVars = environmentProperties == null || environmentProperties.length == 0
                ? null
                : EnvironmentProperty.toMap(Arrays.asList(environmentProperties));
        this.displayNameAttributeName = StringUtils.defaultString(fixEmptyAndTrim(displayNameAttributeName),
                DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME);
        this.mailAddressAttributeName = StringUtils.defaultString(fixEmptyAndTrim(mailAddressAttributeName),
                DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME);
        this.userIdStrategy = userIdStrategy == null ? IdStrategy.CASE_INSENSITIVE : userIdStrategy;
        this.groupIdStrategy = groupIdStrategy == null ? IdStrategy.CASE_INSENSITIVE : groupIdStrategy;
    }

    private Object readResolve() {
        if (managerPassword != null) {
            managerPasswordSecret = Secret.fromString(Scrambler.descramble(managerPassword));
            managerPassword = null;
        }
        if (groupMembershipStrategy == null) {
            groupMembershipStrategy = new FromGroupSearchLDAPGroupMembershipStrategy(groupMembershipFilter);
            groupMembershipFilter = null;
        }
        return this;
    }

    public String getServerUrl() {
        StringBuilder buf = new StringBuilder();
        boolean first = true;
        for (String s: Util.fixNull(server).split("\\s+")) {
            if (s.trim().length() == 0) continue;
            if (first) first = false; else buf.append(' ');
            buf.append(addPrefix(s));
        }
        return buf.toString();
    }

    @Override
    public IdStrategy getUserIdStrategy() {
        return userIdStrategy == null ? IdStrategy.CASE_INSENSITIVE : userIdStrategy;
    }

    @Override
    public IdStrategy getGroupIdStrategy() {
        return groupIdStrategy == null ? IdStrategy.CASE_INSENSITIVE : groupIdStrategy;
    }

    public CacheConfiguration getCache() {
        return cache;
    }

    public Integer getCacheSize() {
        return cache == null ? null : cache.getSize();
    }

    public Integer getCacheTTL() {
        return cache == null ? null : cache.getTtl();
    }

    @Deprecated
    public String getGroupMembershipFilter() {
        return groupMembershipFilter;
    }

    public LDAPGroupMembershipStrategy getGroupMembershipStrategy() {
        return groupMembershipStrategy;
    }

    public String getGroupSearchFilter() {
        return groupSearchFilter;
    }

    public Map<String,String> getExtraEnvVars() {
        return extraEnvVars == null || extraEnvVars.isEmpty()
                ? Collections.<String,String>emptyMap()
                : Collections.unmodifiableMap(extraEnvVars);
    }

    public EnvironmentProperty[] getEnvironmentProperties() {
        if (extraEnvVars == null || extraEnvVars.isEmpty()) {
            return new EnvironmentProperty[0];
        }
        EnvironmentProperty[] result = new EnvironmentProperty[extraEnvVars.size()];
        int i = 0;
        for (Map.Entry<String,String> entry: extraEnvVars.entrySet()) {
            result[i++] = new EnvironmentProperty(entry.getKey(), entry.getValue());
        }
        return result;
    }

    /**
     * Infer the root DN.
     *
     * @return null if not found.
     */
    private String inferRootDN(String server) {
        try {
            Hashtable<String,String> props = new Hashtable<String,String>();
            if(managerDN!=null) {
                props.put(Context.SECURITY_PRINCIPAL,managerDN);
                props.put(Context.SECURITY_CREDENTIALS,getManagerPassword());
            }
            props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            props.put(Context.PROVIDER_URL, toProviderUrl(getServerUrl(), ""));

            DirContext ctx = new InitialDirContext(props);
            Attributes atts = ctx.getAttributes("");
            Attribute a = atts.get("defaultNamingContext");
            if(a!=null && a.get()!=null) // this entry is available on Active Directory. See http://msdn2.microsoft.com/en-us/library/ms684291(VS.85).aspx
                return a.get().toString();

            a = atts.get("namingcontexts");
            if(a==null) {
                LOGGER.warning("namingcontexts attribute not found in root DSE of "+server);
                return null;
            }
            return a.get().toString();
        } catch (NamingException e) {
            LOGGER.log(Level.WARNING,"Failed to connect to LDAP to infer Root DN for "+server,e);
            return null;
        }
    }

    /* package for testing */ static String toProviderUrl(String serverUrl, String rootDN) {
        StringBuilder buf = new StringBuilder();
        boolean first = true;
        for (String s: serverUrl.split("\\s+")) {
            if (s.trim().length() == 0) continue;
            s = getProviderUrl(s, rootDN);
            if (s != null) {
                if (first) first = false; else buf.append(' ');
                buf.append(s);
            }
        }
        return buf.toString();
    }

    private static String getProviderUrl(String server, String rootDN) {
        server = addPrefix(server);
        if (!server.endsWith("/")) {
            server = server + '/';
        }
        if (rootDN != null) {
            rootDN = rootDN.trim();
            if (!rootDN.isEmpty()) {
                try {
                    server = server + new URI(null, null, rootDN, null).toASCIIString();
                } catch(URISyntaxException e) {
                    LOGGER.log(Level.WARNING, "Unable to build URL with rootDN: " + server, e);
                    return null;
                }
            }
        }
        return server;
    }

    public String getManagerPassword() {
        return Secret.toString(managerPasswordSecret);
    }

    public Secret getManagerPasswordSecret() {
        return managerPasswordSecret;
    }

    public String getLDAPURL() {
        return toProviderUrl(getServerUrl(), fixNull(rootDN));
    }

    public String getDisplayNameAttributeName() {
        return StringUtils.defaultString(displayNameAttributeName, DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME);
    }

    public String getMailAddressAttributeName() {
        return StringUtils.defaultString(mailAddressAttributeName, DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME);
    }

    /**
     * Creates security components.
     * @return Created {@link SecurityComponents}
     * @throws IllegalStateException Execution error
     */
    @Override @Nonnull
    public SecurityComponents createSecurityComponents() {
        Binding binding = new Binding();
        binding.setVariable("instance", this);

        final Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins has not been started, or was already shut down");
        }

        BeanBuilder builder = new BeanBuilder(jenkins.pluginManager.uberClassLoader);
        String fileName = "LDAPBindSecurityRealm.groovy";
        try {
            File override = new File(jenkins.getRootDir(), fileName);
            builder.parse(
                    new AutoCloseInputStream(override.exists() ? new FileInputStream(override) :
                        getClass().getResourceAsStream(fileName)), binding);
        } catch (FileNotFoundException e) {
            throw new IllegalStateException("Failed to load "+fileName, e);
        }
        WebApplicationContext appContext = builder.createApplicationContext();

        ldapTemplate = new LdapTemplate(findBean(InitialDirContextFactory.class, appContext));

        if (groupMembershipStrategy != null) {
            groupMembershipStrategy.setAuthoritiesPopulator(findBean(LdapAuthoritiesPopulator.class, appContext));
        }

        return new SecurityComponents(
            new LDAPAuthenticationManager(findBean(AuthenticationManager.class, appContext)),
            new LDAPUserDetailsService(appContext, groupMembershipStrategy));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected UserDetails authenticate(String username, String password) throws AuthenticationException {
        return updateUserDetails((UserDetails) getSecurityComponents().manager.authenticate(
                new UsernamePasswordAuthenticationToken(fixUsername(username), password)).getPrincipal());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        return updateUserDetails(getSecurityComponents().userDetails.loadUserByUsername(fixUsername(username)));
    }

    public Authentication updateUserDetails(Authentication authentication) {
        updateUserDetails((UserDetails) authentication.getPrincipal());
        return authentication;
    }

    public UserDetails updateUserDetails(UserDetails userDetails) {
        if (userDetails instanceof LdapUserDetails) {
            updateUserDetails((LdapUserDetails)userDetails);
        }
        return userDetails;
    }

    public LdapUserDetails updateUserDetails(LdapUserDetails d) {
        hudson.model.User u = hudson.model.User.get(fixUsername(d.getUsername()));
        try {
            Attribute attribute = d.getAttributes().get(getDisplayNameAttributeName());
            String displayName = attribute == null ? null : (String) attribute.get();
            if (StringUtils.isNotBlank(displayName) && u.getId().equals(u.getFullName()) && !u.getFullName().equals(displayName)) {
                u.setFullName(displayName);
            }
        } catch (NamingException e) {
            LOGGER.log(Level.FINEST, "Could not retrieve display name attribute", e);
        }
        if (!disableMailAddressResolver) {
            try {
                Attribute attribute = d.getAttributes().get(getMailAddressAttributeName());
                String mailAddress = attribute == null ? null : (String) attribute.get();
                if (StringUtils.isNotBlank(mailAddress)) {
                    UserProperty existing = u.getProperty(UserProperty.class);
                    if (existing==null || !existing.hasExplicitlyConfiguredAddress())
                        u.addProperty(new Mailer.UserProperty(mailAddress));
                }
            } catch (NamingException e) {
                LOGGER.log(Level.FINEST, "Could not retrieve email address attribute", e);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to associate the e-mail address", e);
            }
        }
        return d;
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupname) throws UsernameNotFoundException, DataAccessException {
        groupname = fixGroupname(groupname);
        Set<String> cachedGroups;
        if (cache != null) {
            final CacheEntry<Set<String>> cached;
            synchronized (this) {
                cached = groupDetailsCache != null ? groupDetailsCache.get(groupname) : null;
            }
            if (cached != null && cached.isValid()) {
                cachedGroups = cached.getValue();
            } else {
                cachedGroups = null;
            }
        } else {
            cachedGroups = null;
        }

        // TODO: obtain a DN instead so that we can obtain multiple attributes later
        String searchBase = groupSearchBase != null ? groupSearchBase : "";
        String searchFilter = groupSearchFilter != null ? groupSearchFilter : GROUP_SEARCH;
        final Set<String> groups = cachedGroups != null
                ? cachedGroups
                : (Set<String>) ldapTemplate
                        .searchForSingleAttributeValues(searchBase, searchFilter, new String[]{groupname}, "cn");
        if (cache != null && cachedGroups == null && !groups.isEmpty()) {
            synchronized (this) {
                if (groupDetailsCache == null) {
                    groupDetailsCache = new CacheMap<String, Set<String>>(cache.getSize());
                }
                groupDetailsCache.put(groupname, new CacheEntry<Set<String>>(cache.getTtl(), groups));
            }
        }

        if(groups.isEmpty())
            throw new UsernameNotFoundException(groupname);

        return new GroupDetailsImpl(fixGroupname(groups.iterator().next()));
    }

    private static String fixGroupname(String groupname) {
        return FORCE_GROUPNAME_LOWERCASE ? groupname.toLowerCase() : groupname;
    }

    private static String fixUsername(String username) {
        return FORCE_USERNAME_LOWERCASE ? username.toLowerCase() : username;
    }

    private static class GroupDetailsImpl extends GroupDetails {

        private String name;

        public GroupDetailsImpl(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    private class LDAPAuthenticationManager implements AuthenticationManager {

        private final AuthenticationManager delegate;

        private LDAPAuthenticationManager(AuthenticationManager delegate) {
            this.delegate = delegate;
        }

        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            return updateUserDetails(delegate.authenticate(authentication));
        }
    }

    public static class LDAPUserDetailsService implements UserDetailsService {
        public final LdapUserSearch ldapSearch;
        public final LdapAuthoritiesPopulator authoritiesPopulator;
        public final LDAPGroupMembershipStrategy groupMembershipStrategy;
        /**
         * {@link BasicAttributes} in LDAP tend to be bulky (about 20K at size), so interning them
         * to keep the size under control. When a programmatic client is not smart enough to
         * reuse a session, this helps keeping the memory consumption low.
         */
        private final LRUMap attributesCache = new LRUMap(32);

        LDAPUserDetailsService(WebApplicationContext appContext) {
            this(appContext, null);
        }

        LDAPUserDetailsService(LdapUserSearch ldapSearch, LdapAuthoritiesPopulator authoritiesPopulator) {
            this(ldapSearch, authoritiesPopulator, null);
        }

        LDAPUserDetailsService(LdapUserSearch ldapSearch, LdapAuthoritiesPopulator authoritiesPopulator, LDAPGroupMembershipStrategy groupMembershipStrategy) {
            this.ldapSearch = ldapSearch;
            this.authoritiesPopulator = authoritiesPopulator;
            this.groupMembershipStrategy = groupMembershipStrategy;
        }

        public LDAPUserDetailsService(WebApplicationContext appContext,
                                      LDAPGroupMembershipStrategy groupMembershipStrategy) {
            this(findBean(LdapUserSearch.class, appContext), findBean(LdapAuthoritiesPopulator.class, appContext), groupMembershipStrategy);
        }

        public LdapUserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            username = fixUsername(username);
            try {
                final Jenkins jenkins = Jenkins.getInstance();
                final SecurityRealm securityRealm = jenkins == null ? null : jenkins.getSecurityRealm();
                if (securityRealm instanceof LDAPSecurityRealm
                        && securityRealm.getSecurityComponents().userDetails == this) {
                    LDAPSecurityRealm ldapSecurityRealm = (LDAPSecurityRealm) securityRealm;
                    if (ldapSecurityRealm.cache != null) {
                        final CacheEntry<LdapUserDetails> cached;
                        synchronized (ldapSecurityRealm) {
                            cached = (ldapSecurityRealm.userDetailsCache != null) ? ldapSecurityRealm.userDetailsCache
                                    .get(username) : null;
                        }
                        if (cached != null && cached.isValid()) {
                            return cached.getValue();
                        }
                    }
                }
                LdapUserDetails ldapUser = ldapSearch.searchForUser(username);
                // LdapUserSearch does not populate granted authorities (group search).
                // Add those, as done in LdapAuthenticationProvider.createUserDetails().
                if (ldapUser != null) {
                    LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence(ldapUser);

                    // intern attributes
                    Attributes v = ldapUser.getAttributes();
                    if (v instanceof BasicAttributes) {// BasicAttributes.equals is what makes the interning possible
                        synchronized (attributesCache) {
                            Attributes vv = (Attributes)attributesCache.get(v);
                            if (vv==null)   attributesCache.put(v,vv=v);
                            user.setAttributes(vv);
                        }
                    }

                    GrantedAuthority[] extraAuthorities = groupMembershipStrategy == null
                            ? authoritiesPopulator.getGrantedAuthorities(ldapUser)
                            : groupMembershipStrategy.getGrantedAuthorities(ldapUser);
                    for (GrantedAuthority extraAuthority : extraAuthorities) {
                        if (FORCE_GROUPNAME_LOWERCASE) {
                            user.addAuthority(new GrantedAuthorityImpl(extraAuthority.getAuthority().toLowerCase()));
                        } else {
                            user.addAuthority(extraAuthority);
                        }
                    }
                    ldapUser = user.createUserDetails();
                }
                if (securityRealm instanceof LDAPSecurityRealm
                        && securityRealm.getSecurityComponents().userDetails == this) {
                    LDAPSecurityRealm ldapSecurityRealm = (LDAPSecurityRealm) securityRealm;
                    if (ldapSecurityRealm.cache != null) {
                        synchronized (ldapSecurityRealm) {
                            if (ldapSecurityRealm.userDetailsCache == null) {
                                ldapSecurityRealm.userDetailsCache =
                                        new CacheMap<String, LdapUserDetails>(ldapSecurityRealm.cache.getSize());
                            }
                            ldapSecurityRealm.userDetailsCache.put(username,
                                    new CacheEntry<LdapUserDetails>(ldapSecurityRealm.cache.getTtl(),
                                            ldapSecurityRealm.updateUserDetails(ldapUser)));
                        }
                    }
                }

                return ldapUser;
            } catch (LdapDataAccessException e) {
                // TODO why not throw all DataAccessException up? that is why it is in the declared clause
                LOGGER.log(Level.WARNING, "Failed to search LDAP for username="+username,e);
                throw new UserMayOrMayNotExistException(e.getMessage(),e);
            } catch (UsernameNotFoundException x) {
                throw x;
            } catch (DataAccessException x) {
                throw x;
            } catch (RuntimeException x) {
                throw new LdapDataAccessException("Failed to search LDAP for " + username + ": " + x, x);
            }
        }
    }

    /**
     * If the security realm is LDAP, try to pick up e-mail address from LDAP.
     */
    @Extension
    public static final class MailAdressResolverImpl extends MailAddressResolver {
        public String findMailAddressFor(User u) {
            final Jenkins jenkins = Jenkins.getInstance();
            if (jenkins == null) {
                return null;
            }
            SecurityRealm realm = jenkins.getSecurityRealm();
            if(!(realm instanceof LDAPSecurityRealm)) { // LDAP not active
                return null;
            }
            if (((LDAPSecurityRealm)realm).disableMailAddressResolver) {
                LOGGER.info( "LDAPSecurityRealm MailAddressResolver is disabled" );
                return null;
            }
            try {
                LdapUserDetails details = (LdapUserDetails)realm.getSecurityComponents().userDetails.loadUserByUsername(u.getId());
                Attribute mail = details.getAttributes().get(((LDAPSecurityRealm)realm).getMailAddressAttributeName());
                if(mail==null)  return null;    // not found
                return (String)mail.get();
            } catch (UsernameNotFoundException e) {
                LOGGER.log(Level.FINE, "Failed to look up LDAP for e-mail address",e);
                return null;
            } catch (DataAccessException e) {
                LOGGER.log(Level.FINE, "Failed to look up LDAP for e-mail address",e);
                return null;
            } catch (NamingException e) {
                LOGGER.log(Level.FINE, "Failed to look up LDAP for e-mail address",e);
                return null;
            } catch (AcegiSecurityException e) {
                LOGGER.log(Level.FINE, "Failed to look up LDAP for e-mail address",e);
                return null;
            }
        }
    }

    /**
     * {@link LdapAuthoritiesPopulator} that adds the automatic 'authenticated' role.
     */
    public static final class AuthoritiesPopulatorImpl extends DefaultLdapAuthoritiesPopulator {
        // Make these available (private in parent class and no get methods!)
        String rolePrefix = "ROLE_";
        boolean convertToUpperCase = true;

        public AuthoritiesPopulatorImpl(InitialDirContextFactory initialDirContextFactory, String groupSearchBase) {
            super(initialDirContextFactory, fixNull(groupSearchBase));

            super.setRolePrefix("");
            super.setConvertToUpperCase(false);
        }

        @Override
        protected Set getAdditionalRoles(LdapUserDetails ldapUser) {
            return Collections.singleton(AUTHENTICATED_AUTHORITY);
        }

        @Override
        public void setRolePrefix(String rolePrefix) {
//            super.setRolePrefix(rolePrefix);
            this.rolePrefix = rolePrefix;
        }

        @Override
        public void setConvertToUpperCase(boolean convertToUpperCase) {
//            super.setConvertToUpperCase(convertToUpperCase);
            this.convertToUpperCase = convertToUpperCase;
        }

        /**
         * Retrieves the group membership in two ways.
         *
         * We'd like to retain the original name, but we historically used to do "ROLE_GROUPNAME".
         * So to remain backward compatible, we make the super class pass the unmodified "groupName",
         * then do the backward compatible translation here, so that the user gets both "ROLE_GROUPNAME" and "groupName".
         */
        @Override
        public Set getGroupMembershipRoles(String userDn, String username) {
            Set<GrantedAuthority> names = super.getGroupMembershipRoles(userDn,username);

            Set<GrantedAuthority> r = new HashSet<GrantedAuthority>(names.size()*2);
            r.addAll(names);

            for (GrantedAuthority ga : names) {
                String role = ga.getAuthority();

                // backward compatible name mangling
                if (convertToUpperCase)
                    role = role.toUpperCase();
                r.add(new GrantedAuthorityImpl(rolePrefix + role));
            }

            return r;
        }
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        public static final String DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME = "displayname";
        public static final String DEFAULT_MAILADDRESS_ATTRIBUTE_NAME = "mail";
        public static final String DEFAULT_USER_SEARCH = "uid={0}";

        public String getDisplayName() {
            return Messages.LDAPSecurityRealm_DisplayName();
        }

        public IdStrategy getDefaultIdStrategy() {
            return IdStrategy.CASE_INSENSITIVE;
        }

        @RequirePOST
        public FormValidation doValidate(StaplerRequest req) throws Exception {
            if (!Jenkins.getActiveInstance().hasPermission(Jenkins.ADMINISTER)) {
                // require admin to test
                return FormValidation.ok();
            }
            // extract the submitted details
            JSONObject json = JSONObject.fromObject(IOUtils.toString(req.getInputStream()));
            String user = json.getString("testUser");
            String password = json.getString("testPassword");
            JSONObject realmCfg = json.getJSONObject("useSecurity").getJSONObject("realm");
            // instantiate the realm
            LDAPSecurityRealm realm = req.bindJSON(LDAPSecurityRealm.class, realmCfg);
            FormValidation connnectionCheck = doCheckServer(realm.getServerUrl(), realm.managerDN, realm.managerPasswordSecret);
            if (connnectionCheck.kind != FormValidation.Kind.OK) {
                return connnectionCheck;
            }

            StringBuilder response = new StringBuilder(1024);
            response.append("<div>Login</div>");
            LdapUserDetails loginDetails = null;
            try {
                // need to access direct so as not to update the user details
                loginDetails = (LdapUserDetails) realm.getSecurityComponents().manager.authenticate(
                        new UsernamePasswordAuthenticationToken(fixUsername(user), password)).getPrincipal();
                response.append("<div class='validation-ok'>Authentication successful</div>");
            } catch (AuthenticationException e) {
                response.append("<div class='error'>Authentication failed</div>");
            }
            Set<String> loginAuthorities = new HashSet<>();
            if (loginDetails != null) {
                response.append("<div class='validation-ok'>User ID: ").append(Util.escape(loginDetails.getUsername()))
                        .append("</div>");
                response.append("<div class='validation-ok'>User DN: ").append(Util.escape(loginDetails.getDn()))
                        .append("</div>");
                Attribute attribute = loginDetails.getAttributes().get(realm.getDisplayNameAttributeName());
                if (attribute == null) {
                    response.append("<div class='warning'>No display name specified for user!<br/>"
                            + "Is the attribute name '")
                            .append(Util.escape(realm.getDisplayNameAttributeName()))
                            .append("' correct?<br/>Available attributes are:<ul>");
                    for (Attribute attr : Collections.list(loginDetails.getAttributes().getAll())) {
                        response.append("<li>").append(Util.escape(attr.getID())).append("</li>");
                    }
                    response.append("</ul></div>");
                } else {
                    try {
                        String displayName = (String) attribute.get();
                        if (displayName != null) {
                            response.append("<div class='validation-ok'>User display name: ")
                                    .append(Util.escape(displayName)).append("</div>");
                        } else {
                            response.append("<div class='warning'>Retrieved display name was empty!<br/>"
                                    + "Is the attribute name '")
                                    .append(Util.escape(realm.getDisplayNameAttributeName()))
                                    .append("' correct?<br/>Available attributes are:<ul>");
                            for (Attribute attr : Collections.list(loginDetails.getAttributes().getAll())) {
                                response.append("<li>").append(Util.escape(attr.getID())).append("</li>");
                            }
                            response.append("</ul></div>");
                        }
                    } catch (NamingException e) {
                        response.append("<div class='error'>Could not retrieve the display name attribute.<br/>"
                                + "Is the attribute name '")
                                .append(Util.escape(realm.getDisplayNameAttributeName()))
                                .append("' correct?<br/>Available attributes are:<ul>");
                        for (Attribute attr : Collections.list(loginDetails.getAttributes().getAll())) {
                            response.append("<li>").append(Util.escape(attr.getID())).append("</li>");
                        }
                        response.append("</ul></div>");
                    }
                }
                if (!realm.disableMailAddressResolver) {
                    attribute = loginDetails.getAttributes().get(realm.getMailAddressAttributeName());
                    if (attribute == null) {
                        response.append("<div class='warning'>No email address specified for user!<br/>"
                                + "Is the attribute name '")
                                .append(Util.escape(realm.getMailAddressAttributeName()))
                                .append("' correct?<br/>Available attributes are:<ul>");
                        for (Attribute attr : Collections.list(loginDetails.getAttributes().getAll())) {
                            response.append("<li>").append(Util.escape(attr.getID())).append("</li>");
                        }
                        response.append("</ul></div>");
                    } else {
                        try {
                            String mailAddress = (String) attribute.get();
                            if (StringUtils.isNotBlank(mailAddress)) {
                                response.append("<div class='validation-ok'>User email: ")
                                        .append(Util.escape(mailAddress)).append("</div>");
                            } else {
                                response.append("<div class='warning'>Retrieved email address was empty!<br/>"
                                        + "Is the attribute name '")
                                        .append(Util.escape(realm.getMailAddressAttributeName()))
                                        .append("' correct?<br/>Available attributes are:<ul>");
                                for (Attribute attr : Collections.list(loginDetails.getAttributes().getAll())) {
                                    response.append("<li>").append(Util.escape(attr.getID())).append("</li>");
                                }
                                response.append("</ul></div>");
                            }
                        } catch (NamingException e) {
                            response.append("<div class='error'>Could not retrieve the email address attribute.<br/>"
                                    + "Is the attribute name '")
                                    .append(Util.escape(realm.getMailAddressAttributeName()))
                                    .append("' correct?<br/>Available attributes are:<ul>");
                            for (Attribute attr : Collections.list(loginDetails.getAttributes().getAll())) {
                                response.append("<li>").append(Util.escape(attr.getID())).append("</li>");
                            }
                            response.append("</ul></div>");
                        }
                    }
                }
                for (GrantedAuthority a : loginDetails.getAuthorities()) {
                    loginAuthorities.add(a.getAuthority());
                }
                if (loginDetails.getAuthorities().length < 1) {
                    response.append("<div class='error'>No group membership reported</div>");
                } else if (loginDetails.getAuthorities().length == 1) {
                    response.append("<div class='warning'>Only basic group membership reported.<br/>");
                    response.append(
                            "If the user is a member of some LDAP groups then the group membership settings are "
                                    + "probably configured incorrectly.</div>");
                } else {
                    response.append("<div class='validation-ok'>Group membership<ul>");
                    for (GrantedAuthority a : loginDetails.getAuthorities()) {
                        if (AUTHENTICATED_AUTHORITY.equals(a)) {
                            continue;
                        }
                        response.append("<li><code>").append(Util.escape(a.getAuthority())).append("</code></li>");
                    }
                    response.append("</ul></div>");
                }
            }

            response.append("<div>Lookup</div>");
            LdapUserDetails lookUpDetails = null;
            try {
                // need to access direct so as not to update the user details
                lookUpDetails =
                        (LdapUserDetails) realm.getSecurityComponents().userDetails
                                .loadUserByUsername(fixUsername(user));
                response.append("<div class='validation-ok'>User lookup: successful</div>");
            } catch (UserMayOrMayNotExistException e1) {
                response.append(
                        "<div class='warning'>User lookup: user may or may not exist.<br/>Is a Manager DN and "
                                + "password required to lookup user details?</div>");
            } catch (UsernameNotFoundException e1) {
                response.append(
                        "<div class='error'>User lookup: user does not exist.<br/>Is a Manager DN and password "
                                + "required to lookup user details?<br/>Are the user search base and user search "
                                + "filter settings correct?</div>");
            } catch (LdapDataAccessException e) {
                Throwable cause = e.getCause();
                while (cause != null && !(cause instanceof BadCredentialsException)) {
                    cause = cause.getCause();
                }
                if (cause != null) {
                    response.append("<div class='error'>User lookup: bad credentials for user lookup.<br/>"
                            + "Is the Manager DN and password correct?</div>");
                } else {
                    response.append("<div class='error'>User lookup: failed<br/>");
                    response.append(Util.escape(e.getLocalizedMessage()));
                    response.append("</div>");
                }
            }
            Set<String> lookupAuthorities = new HashSet<>();
            if (lookUpDetails != null) {
                for (GrantedAuthority a : lookUpDetails.getAuthorities()) {
                    lookupAuthorities.add(a.getAuthority());
                }
                if (loginDetails == null || !loginAuthorities.equals(lookupAuthorities)) {
                    // report the group details
                    if (lookUpDetails.getAuthorities().length < 1) {
                        response.append("<div class='error'>No group membership reported</div>");
                    } else if (lookUpDetails.getAuthorities().length == 1) {
                        response.append("<div class='warning'>Only basic group membership reported.<br/>If the user "
                                + "is a member of some LDAP groups then the group membership settings are probably "
                                + "configured incorrectly.</div>");
                    } else {
                        response.append("<div class='validation-ok'>Group membership<ul>");
                        for (GrantedAuthority a : lookUpDetails.getAuthorities()) {
                            if (AUTHENTICATED_AUTHORITY.equals(a)) {
                                continue;
                            }
                            response.append("<li><code>")
                                    .append(Util.escape(a.getAuthority()))
                                    .append("</code></li>");
                        }
                        response.append("</ul></div>");
                    }
                }
            }
            if (loginDetails != null && lookUpDetails != null) {
                if (loginAuthorities.equals(lookupAuthorities)) {
                    response.append("<div class='validation-ok'>Lookup group details match login group details</div>");
                } else {
                    response.append("<div class='error'>Lookup group details do not match login group details</div>");
                }
            }
            Set<String> groups = new HashSet<>(loginAuthorities);
            Set<String> badGroups = new TreeSet<>();
            groups.addAll(lookupAuthorities);
            groups.remove(AUTHENTICATED_AUTHORITY.getAuthority());
            for (String group : groups) {
                try {
                    realm.loadGroupByGroupname(group);
                } catch (UserMayOrMayNotExistException e) {
                    badGroups.add(group);
                } catch (UsernameNotFoundException e) {
                    badGroups.add(group);
                }
            }
            if (groups.isEmpty()) {
                response.append(
                        "<div class='warning'>Group lookup: could not verify.<br/>Please try with a user that is a member"
                                + " of at least one group.</div>");
            } else if (badGroups.isEmpty()) {
                response.append("<div class='validation-ok'>Group lookup: successful for ").append(groups.size())
                        .append(" groups</div>");
            } else {
                response.append("<div class='warning'>Group lookup: failed for groups:<ul>");
                for (String group:badGroups) {
                    response.append("<li>").append(Util.escape(group)).append("</li>");
                }
                response.append("</ul>Is a Manager DN and password required to lookup group details?<br/>");
                response.append("Are the group search base and group search filter settings correct?</div>");
            }

            return FormValidation.okWithMarkup(response.toString());
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
                props.put(Context.PROVIDER_URL, toProviderUrl(server, ""));

                DirContext ctx = new InitialDirContext(props);
                ctx.getAttributes("");
                return FormValidation.ok();   // connected
            } catch (NamingException e) {
                // trouble-shoot
                Matcher m = Pattern.compile("(ldaps?://)?([^:]+)(?:\\:(\\d+))?(\\s+(ldaps?://)?([^:]+)(?:\\:(\\d+))?)*").matcher(server.trim());
                if(!m.matches())
                    return FormValidation.error(Messages.LDAPSecurityRealm_SyntaxOfServerField());

                try {
                    InetAddress adrs = InetAddress.getByName(m.group(2));
                    int port = m.group(1)!=null ? 636 : 389;
                    if(m.group(3)!=null)
                        port = Integer.parseInt(m.group(3));
                    Socket s = new Socket(adrs,port);
                    s.close();
                } catch (UnknownHostException x) {
                    return FormValidation.error(Messages.LDAPSecurityRealm_UnknownHost(x.getMessage()));
                } catch (IOException x) {
                    return FormValidation.error(x,Messages.LDAPSecurityRealm_UnableToConnect(server, x.getMessage()));
                }

                // otherwise we don't know what caused it, so fall back to the general error report
                // getMessage() alone doesn't offer enough
                return FormValidation.error(e,Messages.LDAPSecurityRealm_UnableToConnect(server, e));
            } catch (NumberFormatException x) {
                // The getLdapCtxInstance method throws this if it fails to parse the port number
                return FormValidation.error(Messages.LDAPSecurityRealm_InvalidPortNumber());
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
     * If the given "server name" is just a host name (plus optional host name), add ldap:// prefix.
     * Otherwise assume it already contains the scheme, and leave it intact.
     */
    private static String addPrefix(String server) {
        if(server.contains("://"))  return server;
        else    return "ldap://"+server;
    }

    private static final Logger LOGGER = Logger.getLogger(LDAPSecurityRealm.class.getName());

    /**
     * LDAP filter to look for groups by their names.
     *
     * "{0}" is the group name as given by the user.
     * See http://msdn.microsoft.com/en-us/library/aa746475(VS.85).aspx for the syntax by example.
     * WANTED: The specification of the syntax.
     */
    public static final String GROUP_SEARCH = System.getProperty(LDAPSecurityRealm.class.getName()+".groupSearch",
            "(& (cn={0}) (| (objectclass=groupOfNames) (objectclass=groupOfUniqueNames) (objectclass=posixGroup)))");

    public static class CacheConfiguration extends AbstractDescribableImpl<CacheConfiguration> {
        private final int size;
        private final int ttl;

        @DataBoundConstructor
        public CacheConfiguration(int size, int ttl) {
            this.size = Math.max(10, Math.min(size, 1000));
            this.ttl = Math.max(30, Math.min(ttl, 3600));
        }

        public int getSize() {
            return size;
        }

        public int getTtl() {
            return ttl;
        }

        @Extension public static class DescriptorImpl extends Descriptor<CacheConfiguration> {

            @Override public String getDisplayName() {
                return "";
            }

            public ListBoxModel doFillSizeItems() {
                ListBoxModel m = new ListBoxModel();
                m.add("10");
                m.add("20");
                m.add("50");
                m.add("100");
                m.add("200");
                m.add("500");
                m.add("1000");
                return m;
            }

            public ListBoxModel doFillTtlItems() {
                ListBoxModel m = new ListBoxModel();
                for (int ttl: new int[]{30, 60, 120, 300, 600, 900, 1800, 3600}) {
                    m.add(Util.getTimeSpanString(ttl*1000L), Integer.toString(ttl));
                }
                return m;
            }

        }
    }

    private static class CacheEntry<T> {
        private final long expires;
        private final T value;

        public CacheEntry(int ttlSeconds, T value) {
            this.expires = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(ttlSeconds);
            this.value = value;
        }

        public T getValue() {
            return value;
        }

        public boolean isValid() {
            return System.currentTimeMillis() < expires;
        }
    }

    /**
     * While we could use Guava's CacheBuilder the method signature changes make using it problematic.
     * Safer to roll our own and ensure compatibility across as wide a range of Jenkins versions as possible.
     *
     * @param <K> Key type
     * @param <V> Cache entry type
     */
    private static class CacheMap<K, V> extends LinkedHashMap<K, CacheEntry<V>> {

        private final int cacheSize;

        public CacheMap(int cacheSize) {
            super(cacheSize + 1); // prevent realloc when hitting cache size limit
            this.cacheSize = cacheSize;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<K, CacheEntry<V>> eldest) {
            return size() > cacheSize || eldest.getValue() == null || !eldest.getValue().isValid();
        }
    }

    public static class EnvironmentProperty extends AbstractDescribableImpl<EnvironmentProperty> implements Serializable {
        private final String name;
        private final String value;

        @DataBoundConstructor
        public EnvironmentProperty(String name, String value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }

        public static Map<String,String> toMap(List<EnvironmentProperty> properties) {
            if (properties != null) {
                final Map<String, String> result = new LinkedHashMap<String, String>();
                for (EnvironmentProperty property:properties) {
                    result.put(property.getName(), property.getValue());
                }
                return result;
            }
            return null;
        }

        @Extension
        public static class DescriptorImpl extends Descriptor<EnvironmentProperty> {

            @Override
            public String getDisplayName() {
                return "";
            }
        }
    }
}
