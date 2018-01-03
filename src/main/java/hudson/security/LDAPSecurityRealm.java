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
package hudson.security;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.Main;
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
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import jenkins.security.plugins.ldap.FromGroupSearchLDAPGroupMembershipStrategy;
import jenkins.security.plugins.ldap.LDAPConfiguration;
import jenkins.security.plugins.ldap.LDAPGroupMembershipStrategy;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.acegisecurity.AcegiSecurityException;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.ldap.LdapUserSearch;
import org.acegisecurity.ldap.search.FilterBasedLdapUserSearch;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.ldap.LdapAuthenticationProvider;
import org.acegisecurity.providers.ldap.LdapAuthenticator;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.providers.ldap.populator.DefaultLdapAuthoritiesPopulator;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.apache.commons.collections.map.LRUMap;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.springframework.dao.DataAccessException;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.ldap.Control;
import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

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
    @Deprecated @Restricted(NoExternalUse.class)
    public transient String server;

    /**
     * The root DN to connect to. Normally something like "dc=sun,dc=com"
     *
     * How do I infer this?
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    @Deprecated @Restricted(NoExternalUse.class)
    public transient String rootDN;

    /**
     * Allow the rootDN to be inferred? Default is false.
     * If true, allow rootDN to be blank.
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    @Deprecated @Restricted(NoExternalUse.class)
    public transient boolean inhibitInferRootDN;

    /**
     * Specifies the relative DN from {@link #rootDN the root DN}.
     * This is used to narrow down the search space when doing user search.
     *
     * Something like "ou=people" but can be empty.
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    @Deprecated @Restricted(NoExternalUse.class)
    public transient String userSearchBase;

    /**
     * Query to locate an entry that identifies the user, given the user name string.
     *
     * Normally "uid={0}"
     *
     * @see FilterBasedLdapUserSearch
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    @Deprecated @Restricted(NoExternalUse.class)
    public transient String userSearch;
    
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
    @Deprecated @Restricted(NoExternalUse.class)
    public transient String groupSearchBase;

    /**
     * Query to locate an entry that identifies the group, given the group name string. If non-null it will override
     * the default specified by {@link #GROUP_SEARCH}
     *
     * @since 1.5
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    @Deprecated @Restricted(NoExternalUse.class)
    public transient String groupSearchFilter;

    /**
     * Query to locate the group entries that a user belongs to, given the user object. <code>{0}</code>
     * is the user's full DN while {1} is the username. If non-null it will override the default specified in
     * {@code LDAPBindSecurityRealm.groovy}
     *
     * @since 1.5
     * @deprecated use {@link #groupMembershipStrategy}
     */
    @Deprecated @Restricted(NoExternalUse.class)
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD", 
        justification = "This public field is exposed to the plugin's API")
    public transient String groupMembershipFilter;

    /**
     * @since 2.0
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    @Deprecated @Restricted(NoExternalUse.class)
    public /*effectively final*/ transient LDAPGroupMembershipStrategy groupMembershipStrategy;

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
    @Deprecated @Restricted(NoExternalUse.class)
    public transient String managerDN;

    @Deprecated @Restricted(NoExternalUse.class)
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD", 
        justification = "This public field is exposed to the plugin's API")
    private transient String managerPassword;

    /**
     * Password used to first bind to LDAP.
     */
    @Deprecated @Restricted(NoExternalUse.class)
    private transient Secret managerPasswordSecret;

    /**
     * @since 1.2
     */
    @SuppressFBWarnings(value = "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD",
        justification = "This public field is exposed to the plugin's API")
    public final boolean disableMailAddressResolver;

    private List<LDAPConfiguration> configurations;

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

    @Deprecated @Restricted(NoExternalUse.class)
    private transient Map<String,String> extraEnvVars;

    @Deprecated @Restricted(NoExternalUse.class)
    private transient String displayNameAttributeName;

    @Deprecated @Restricted(NoExternalUse.class)
    private transient String mailAddressAttributeName;

    private final IdStrategy userIdStrategy;

    private final IdStrategy groupIdStrategy;

    private boolean disableRolePrefixing;

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

    /**
     * @deprecated retained for backwards binary compatibility.
     */
    @Deprecated
    public LDAPSecurityRealm(String server, String rootDN, String userSearchBase, String userSearch, String groupSearchBase, String groupSearchFilter, LDAPGroupMembershipStrategy groupMembershipStrategy, String managerDN, Secret managerPasswordSecret, boolean inhibitInferRootDN, boolean disableMailAddressResolver, CacheConfiguration cache, EnvironmentProperty[] environmentProperties, String displayNameAttributeName, String mailAddressAttributeName, IdStrategy userIdStrategy, IdStrategy groupIdStrategy) {
        this(createLdapConfiguration(server, rootDN, userSearchBase, userSearch, groupSearchBase, groupSearchFilter, groupMembershipStrategy, managerDN, managerPasswordSecret, inhibitInferRootDN, environmentProperties, displayNameAttributeName, mailAddressAttributeName),
                disableMailAddressResolver, cache, userIdStrategy, groupIdStrategy);
    }

    @DataBoundConstructor
    public LDAPSecurityRealm(List<LDAPConfiguration> configurations, boolean disableMailAddressResolver, CacheConfiguration cache, IdStrategy userIdStrategy, IdStrategy groupIdStrategy) {
        if (configurations == null || configurations.isEmpty()) {
            //Correct FormException should be handled by DescriptorImpl.newInstance
            throw new IllegalArgumentException(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AtLeastOne());
        }
        if (configurations.size() > 1) {
            //Configuration as code is a hot topic these days, so newInstance might not have been used.
            if (!Main.isUnitTest || !Boolean.getBoolean(LDAPSecurityRealm.class.getName() + "do a bad thing during testing")) {  //Only during unit testing do we want to work around this limitation, but only explicitly.
                for (int i = 0; i < configurations.size(); i++) {
                    LDAPConfiguration ci = configurations.get(i);
                    for (int k = i + 1; k < configurations.size(); k++) {
                        LDAPConfiguration ck = configurations.get(k);
                        if (ci.isConfiguration(ck.getId())) {
                            throw new IllegalArgumentException(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_NotSameServer());
                        }
                    }
                }
            }
        }
        this.configurations = configurations;
        this.disableMailAddressResolver = disableMailAddressResolver;
        this.cache = cache;
        this.userIdStrategy = userIdStrategy;
        this.groupIdStrategy = groupIdStrategy;
    }

    private static List<LDAPConfiguration> createLdapConfiguration(String server, String rootDN, String userSearchBase, String userSearch, String groupSearchBase, String groupSearchFilter, LDAPGroupMembershipStrategy groupMembershipStrategy, String managerDN, Secret managerPasswordSecret, boolean inhibitInferRootDN, EnvironmentProperty[] environmentProperties, String displayNameAttributeName, String mailAddressAttributeName) {
        LDAPConfiguration conf = new LDAPConfiguration(server, rootDN, inhibitInferRootDN, managerDN, managerPasswordSecret);
        conf.setUserSearchBase(userSearchBase);
        conf.setUserSearch(userSearch);
        conf.setGroupSearchBase(groupSearchBase);
        conf.setGroupSearchFilter(groupSearchFilter);
        conf.setGroupMembershipStrategy(groupMembershipStrategy);
        conf.setEnvironmentProperties(environmentProperties);
        conf.setDisplayNameAttributeName(displayNameAttributeName);
        conf.setMailAddressAttributeName(mailAddressAttributeName);
        return Collections.singletonList(conf);
    }

    public List<LDAPConfiguration> getConfigurations() {
        return configurations;
    }

    private boolean hasConfiguration() {
        return configurations != null && !configurations.isEmpty();
    }

    public boolean isDisableRolePrefixing() {
        return disableRolePrefixing;
    }

    @DataBoundSetter
    public void setDisableRolePrefixing(boolean disableRolePrefixing) {
        this.disableRolePrefixing = disableRolePrefixing;
    }

    private Object readResolve() {
        if (managerPassword != null) {
            managerPasswordSecret = Secret.fromString(Scrambler.descramble(managerPassword));
            managerPassword = null;
        }
        if (server != null) {
            LDAPConfiguration conf = new LDAPConfiguration(server, rootDN, inhibitInferRootDN, managerDN, managerPasswordSecret);
            server = null;
            rootDN = null;
            managerDN = null;
            managerPasswordSecret = null;
            conf.setMailAddressAttributeName(mailAddressAttributeName);
            mailAddressAttributeName = null;
            conf.setDisplayNameAttributeName(displayNameAttributeName);
            displayNameAttributeName = null;
            conf.setExtraEnvVars(extraEnvVars);
            extraEnvVars = null;
            if (groupMembershipStrategy == null) {
                conf.setGroupMembershipStrategy(new FromGroupSearchLDAPGroupMembershipStrategy(groupMembershipFilter));
                groupMembershipFilter = null;
            } else {
                conf.setGroupMembershipStrategy(groupMembershipStrategy);
                groupMembershipStrategy = null;
            }
            conf.setGroupSearchBase(groupSearchBase);
            groupSearchBase = null;
            conf.setGroupSearchFilter(groupSearchFilter);
            groupSearchFilter = null;
            conf.setUserSearch(userSearch);
            userSearch = null;
            conf.setUserSearchBase(userSearchBase);
            userSearchBase = null;
            this.configurations = new ArrayList<>();
            configurations.add(conf);
        }
        return this;
    }

    @Deprecated @Restricted(DoNotUse.class)
    public String getServerUrl() {
        return hasConfiguration() ? configurations.get(0).getServerUrl() : null;
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

    @Deprecated @Restricted(DoNotUse.class)
    public String getGroupMembershipFilter() {
        return hasConfiguration() ? configurations.get(0).getGroupSearchFilter() : null;
    }

    @Deprecated @Restricted(DoNotUse.class)
    public LDAPGroupMembershipStrategy getGroupMembershipStrategy() {
        return hasConfiguration() ? configurations.get(0).getGroupMembershipStrategy() : null;
    }

    @Deprecated @Restricted(DoNotUse.class)
    public String getGroupSearchFilter() {
        return hasConfiguration() ? configurations.get(0).getGroupSearchFilter() : null;
    }

    @Deprecated @Restricted(DoNotUse.class)
    public Map<String,String> getExtraEnvVars() {
        return hasConfiguration() ? configurations.get(0).getExtraEnvVars() : Collections.<String, String>emptyMap();
    }

    @Deprecated @Restricted(DoNotUse.class)
    public EnvironmentProperty[] getEnvironmentProperties() {
        return hasConfiguration() ? configurations.get(0).getEnvironmentProperties() : new EnvironmentProperty[0];
    }

    @Deprecated @Restricted(DoNotUse.class)
    public String getManagerPassword() {
        return hasConfiguration() ? configurations.get(0).getManagerPassword() : null;
    }

    @Deprecated @Restricted(DoNotUse.class)
    public Secret getManagerPasswordSecret() {
        return hasConfiguration() ? configurations.get(0).getManagerPasswordSecret() : null;
    }

    @Deprecated @Restricted(DoNotUse.class)
    public String getLDAPURL() {
        return hasConfiguration() ? configurations.get(0).getLDAPURL() : null;
    }

    @Deprecated @Restricted(DoNotUse.class)
    public String getDisplayNameAttributeName() {
        return hasConfiguration() ? configurations.get(0).getDisplayNameAttributeName() : DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME;
    }

    @Deprecated @Restricted(DoNotUse.class)
    public String getMailAddressAttributeName() {
        return hasConfiguration() ? configurations.get(0).getMailAddressAttributeName() : DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME;
    }

    @CheckForNull @Restricted(NoExternalUse.class)
    public LDAPConfiguration getConfigurationFor(LdapUserDetails d) {
        if (d instanceof DelegatedLdapUserDetails) {
            return getConfigurationFor(((DelegatedLdapUserDetails) d).getConfigurationId());
        } else if (hasConfiguration() && configurations.size() == 1) {
            return configurations.get(0);
        } else {
            return null;
        }
    }

    @Restricted(NoExternalUse.class)
    public boolean hasMultiConfiguration() {
        return hasConfiguration() && configurations.size() > 1;
    }

    @CheckForNull @Restricted(NoExternalUse.class)
    public LDAPConfiguration getConfigurationFor(String configurationId) {
        if (configurations != null) {
            for (LDAPConfiguration configuration : configurations) {
                if (configuration.isConfiguration(configurationId)) {
                    return configuration;
                }
            }
            if (configurations.size() == 1) {
                return configurations.get(0);
            }
        }
        return null;
    }

    @CheckForNull
    private static LDAPConfiguration _getConfigurationFor(String configurationId) {
        final SecurityRealm securityRealm = Jenkins.getActiveInstance().getSecurityRealm();
        if (securityRealm instanceof LDAPSecurityRealm) {
            return ((LDAPSecurityRealm) securityRealm).getConfigurationFor(configurationId);
        }

        return null;
    }

    @Restricted(NoExternalUse.class)
    public static String toProviderUrl(String serverUrl, String rootDN) {
        StringBuilder buf = new StringBuilder();
        boolean first = true;
        for (String s : serverUrl.split("\\s+")) {
            if (s.trim().length() == 0) continue;
            s = getProviderUrl(s, rootDN);
            if (s != null) {
                if (first) {
                    first = false;
                } else {
                    buf.append(' ');
                }
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
                } catch (URISyntaxException e) {
                    LOGGER.log(Level.WARNING, "Unable to build URL with rootDN: " + server, e);
                    return null;
                }
            }
        }
        return server;
    }

    /**
     * Creates security components.
     * @return Created {@link SecurityComponents}
     * @throws IllegalStateException Execution error
     */
    @Override @Nonnull
    public SecurityComponents createSecurityComponents() {
        if (configurations.size() > 1) {
            DelegateLDAPUserDetailsService details = new DelegateLDAPUserDetailsService();
            LDAPAuthenticationManager manager = new LDAPAuthenticationManager(details);
            for (LDAPConfiguration conf : configurations) {
                WebApplicationContext appContext = conf.createApplicationContext(this, false);
                manager.addDelegate(findBean(AuthenticationManager.class, appContext), conf.getId());
                details.addDelegate(new LDAPUserDetailsService(appContext, conf.getGroupMembershipStrategy(), conf.getId()));
            }
            return new SecurityComponents(manager, details);
        } else {
            final LDAPConfiguration conf = configurations.get(0);
            WebApplicationContext appContext = conf.createApplicationContext(this, true);
            final LDAPAuthenticationManager manager = new LDAPAuthenticationManager();
            manager.addDelegate(findBean(AuthenticationManager.class, appContext), "");
            return new SecurityComponents(
                    manager,
                    new LDAPUserDetailsService(appContext, conf.getGroupMembershipStrategy(), null)
            );
        }
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
        LDAPConfiguration configuration = getConfigurationFor(d);
        String displayNameAttributeName;
        String mailAddressAttributeName;
        if (configuration != null) {
            displayNameAttributeName = configuration.getDisplayNameAttributeName();
            mailAddressAttributeName = configuration.getMailAddressAttributeName();
            if (StringUtils.isEmpty(displayNameAttributeName)) {
                displayNameAttributeName = DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME;
            }
            if (StringUtils.isEmpty(mailAddressAttributeName)) {
                mailAddressAttributeName = DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME;
            }
        } else {
            displayNameAttributeName = DescriptorImpl.DEFAULT_DISPLAYNAME_ATTRIBUTE_NAME;
            mailAddressAttributeName = DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME;
        }
        try {
            Attribute attribute = d.getAttributes().get(displayNameAttributeName);
            String displayName = attribute == null ? null : (String) attribute.get();
            if (StringUtils.isNotBlank(displayName) && u.getId().equals(u.getFullName()) && !u.getFullName().equals(displayName)) {
                u.setFullName(displayName);
            }
        } catch (NamingException e) {
            LOGGER.log(Level.FINEST, "Could not retrieve display name attribute", e);
        }
        if (!disableMailAddressResolver) {
            try {
                Attribute attribute = d.getAttributes().get(mailAddressAttributeName);
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

        final Set<String> groups = cachedGroups != null
                ? cachedGroups
                : searchForGroupName(groupname);
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

    private Set<String> searchForGroupName(String groupname) {
        Set<String> groups = new TreeSet<>();
        for (LDAPConfiguration conf : configurations) {
            String searchBase = conf.getGroupSearchBase() != null ? conf.getGroupSearchBase() : "";
            String searchFilter = conf.getGroupSearchFilter() != null ? conf.getGroupSearchFilter() : GROUP_SEARCH;
            groups.addAll(conf.getLdapTemplate().searchForSingleAttributeValues(searchBase, searchFilter, new String[]{groupname}, "cn"));
        }
        return groups;
    }

    private static String fixGroupname(String groupname) {
        return FORCE_GROUPNAME_LOWERCASE ? groupname.toLowerCase() : groupname;
    }

    private static String fixUsername(String username) {
        return FORCE_USERNAME_LOWERCASE ? username.toLowerCase() : username;
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
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
        private final List<ManagerEntry> delegates = new ArrayList<>();;
        private final DelegateLDAPUserDetailsService detailsService;

        private LDAPAuthenticationManager() {
            detailsService = null;
        }

        private LDAPAuthenticationManager(DelegateLDAPUserDetailsService detailsService) {
            this.detailsService = detailsService;
        }

        private void addDelegate(final AuthenticationManager delegate, final String configurationId) {
            this.delegates.add(new ManagerEntry(delegate, configurationId));
        }

        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            if (delegates.size() == 1) {
                try {
                    return updateUserDetails(delegates.get(0).delegate.authenticate(authentication));
                } catch (AuthenticationServiceException e) {
                    LOGGER.log(Level.WARNING, "Failed communication with ldap server.", e);
                    throw e;
                }
            }
            BadCredentialsException lastException = null;
            for (ManagerEntry delegate : delegates) {
                try {
                    Authentication a = delegate.delegate.authenticate(authentication);
                    return updateUserDetails(new DelegatedLdapAuthentication(a, delegate.configurationId));
                } catch (BadCredentialsException e) {
                    if (detailsService != null && delegates.size() > 1) {
                        try {
                            UserDetails details = detailsService.loadUserByUsername(delegate.configurationId, String.valueOf(authentication.getPrincipal()));
                            if (details != null) {
                                throw e; //the user actually exists on this server, so we should stop here and report
                            }
                        } catch (UsernameNotFoundException e1) {
                            lastException = e; //all is as intended, let's move along
                        }
                    } else {
                        lastException = e;
                    }
                } catch (AuthenticationServiceException e) {
                    final LDAPConfiguration configuration = getConfigurationFor(delegate.configurationId);
                    LOGGER.log(Level.WARNING,
                            String.format("Failed communication with ldap server %s (%s)",
                                    delegate.configurationId, configuration != null ? configuration.getServer() : "null"),
                            e);
                    throw e;
                }
            }
            if (lastException != null) {
                throw lastException;
            } else {
                throw new UserMayOrMayNotExistException("No ldap server configuration", authentication);
            }
        }

        private class ManagerEntry {
            final AuthenticationManager delegate;
            final String configurationId;

            public ManagerEntry(AuthenticationManager delegate, String configurationId) {
                this.delegate = delegate;
                this.configurationId = configurationId;
            }
        }
    }

    /*package access for testability*/
    static class DelegatedLdapAuthentication implements Authentication {
        private final Authentication delegate;
        private final String configurationId;

        public DelegatedLdapAuthentication(Authentication delegate, String configurationId) {
            this.delegate = delegate;
            this.configurationId = configurationId;
        }

        @Override
        public GrantedAuthority[] getAuthorities() {
            return delegate.getAuthorities();
        }

        @Override
        public Object getCredentials() {
            return delegate.getCredentials();
        }

        @Override
        public Object getDetails() {
            return delegate.getDetails();
        }

        @Override
        public Object getPrincipal() {
            Object principal = delegate.getPrincipal();
            if (principal instanceof LdapUserDetails && !(principal instanceof DelegatedLdapUserDetails)) {
                return new DelegatedLdapUserDetails((LdapUserDetails) principal, this.configurationId);
            } else {
                return principal;
            }
        }

        @Override
        public boolean isAuthenticated() {
            return delegate.isAuthenticated();
        }

        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
            delegate.setAuthenticated(isAuthenticated);
        }

        @Override
        public String getName() {
            return delegate.getName();
        }

        public Authentication getDelegate() {
            return delegate;
        }

        public String getConfigurationId() {
            return configurationId;
        }
    }

    /*package access for testability*/
    static class DelegatedLdapUserDetails implements LdapUserDetails, Serializable {
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

    private static class DelegateLDAPUserDetailsService implements UserDetailsService {
        private final List<LDAPUserDetailsService> delegates;

        public DelegateLDAPUserDetailsService() {
            delegates = new ArrayList<>();
        }

        public void addDelegate(LDAPUserDetailsService delegate) {
            delegates.add(delegate);
        }

        public boolean contains(LDAPUserDetailsService delegate) {
            return delegates.contains(delegate);
        }

        /**
         * Tries to load the user from a specified server key
         * @param configurationId the server to specifically load from
         * @param username the username to search
         * @return the user details or {@code null} if the server configuration could not be found
         * @throws UsernameNotFoundException if the user could not be found on the given server
         * @throws DataAccessException if some communication error occured
         * @see #loadUserByUsername(String)
         */
        public DelegatedLdapUserDetails loadUserByUsername(String configurationId, String username) throws UsernameNotFoundException, DataAccessException {
            for (LDAPUserDetailsService delegate : delegates) {
                if (delegate.configurationId.equals(configurationId)) {
                    try {
                        LdapUserDetails userDetails = delegate.loadUserByUsername(username);
                        if (userDetails instanceof DelegatedLdapUserDetails) {
                            return (DelegatedLdapUserDetails)userDetails;
                        } else {
                            return new DelegatedLdapUserDetails(userDetails, delegate.configurationId);
                        }
                    } catch (DataAccessException e) {
                        final LDAPConfiguration configuration = _getConfigurationFor(delegate.configurationId);
                        LOGGER.log(Level.WARNING,
                                String.format("Failed communication with ldap server %s (%s)",
                                        delegate.configurationId, configuration != null ? configuration.getServer() : "null"),
                                e);
                        throw e;
                    }
                }
            }
            return null;
        }

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            UsernameNotFoundException lastUNFE = null;
            for (LDAPUserDetailsService delegate : delegates) {
                try {
                    LdapUserDetails userDetails = delegate.loadUserByUsername(username);
                    if (userDetails instanceof DelegatedLdapUserDetails) {
                        return userDetails;
                    } else {
                        return new DelegatedLdapUserDetails(userDetails, delegate.configurationId);
                    }
                } catch (UsernameNotFoundException e) {
                    lastUNFE = e;
                } catch (DataAccessException e) {
                    LDAPConfiguration configuration = _getConfigurationFor(delegate.configurationId);
                    LOGGER.log(Level.WARNING,
                            "LDAP connection "
                                    + delegate.configurationId
                                    + (configuration != null ? "("+configuration.getServer()+")" : "")
                                    + " seems to be broken, will _not_ try the next configuration.", e);
                    throw e;
                }
            }
            if (lastUNFE != null) {
                throw  lastUNFE;
            } else {
                throw new UsernameNotFoundException(username);
            }
        }
    }

    public static class LDAPUserDetailsService implements UserDetailsService {
        public final LdapUserSearch ldapSearch;
        public final LdapAuthoritiesPopulator authoritiesPopulator;
        public final LDAPGroupMembershipStrategy groupMembershipStrategy;
        public final String configurationId;
        /**
         * {@link BasicAttributes} in LDAP tend to be bulky (about 20K at size), so interning them
         * to keep the size under control. When a programmatic client is not smart enough to
         * reuse a session, this helps keeping the memory consumption low.
         */
        private final LRUMap attributesCache = new LRUMap(32);

        @Deprecated
        LDAPUserDetailsService(WebApplicationContext appContext) {
            this(appContext, null, null);
        }

        @Deprecated
        LDAPUserDetailsService(LdapUserSearch ldapSearch, LdapAuthoritiesPopulator authoritiesPopulator) {
            this(ldapSearch, authoritiesPopulator, null, null);
        }

        LDAPUserDetailsService(LdapUserSearch ldapSearch, LdapAuthoritiesPopulator authoritiesPopulator, LDAPGroupMembershipStrategy groupMembershipStrategy, String configurationId) {
            this.ldapSearch = ldapSearch;
            this.authoritiesPopulator = authoritiesPopulator;
            this.groupMembershipStrategy = groupMembershipStrategy;
            this.configurationId = configurationId;
        }

        @Deprecated
        public LDAPUserDetailsService(WebApplicationContext appContext,
                                      LDAPGroupMembershipStrategy groupMembershipStrategy) {
            this(findBean(LdapUserSearch.class, appContext), findBean(LdapAuthoritiesPopulator.class, appContext), groupMembershipStrategy, null);
        }

        public LDAPUserDetailsService(WebApplicationContext appContext,
                                      LDAPGroupMembershipStrategy groupMembershipStrategy, String configurationId) {
            this(findBean(LdapUserSearch.class, appContext), findBean(LdapAuthoritiesPopulator.class, appContext), groupMembershipStrategy, configurationId);
        }

        @SuppressFBWarnings(value = "RCN_REDUNDANT_NULLCHECK_OF_NONNULL_VALUE", justification = "Only on newer core versions") //TODO remove when core is bumped
        public LdapUserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            username = fixUsername(username);
            try {
                final Jenkins jenkins = Jenkins.getInstance();
                final SecurityRealm securityRealm = jenkins == null ? null : jenkins.getSecurityRealm();
                if (securityRealm instanceof LDAPSecurityRealm
                        && (securityRealm.getSecurityComponents().userDetails == this
                        || (securityRealm.getSecurityComponents().userDetails instanceof DelegateLDAPUserDetailsService
                        && ((DelegateLDAPUserDetailsService) securityRealm.getSecurityComponents().userDetails).contains(this))
                        )) {
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
                    if (StringUtils.isNotEmpty(configurationId)) {
                        ldapUser = new DelegatedLdapUserDetails(user.createUserDetails(), configurationId);
                    } else {
                        ldapUser = user.createUserDetails();
                    }
                }
                if (securityRealm instanceof LDAPSecurityRealm
                        && (securityRealm.getSecurityComponents().userDetails == this
                            || (securityRealm.getSecurityComponents().userDetails instanceof DelegateLDAPUserDetailsService
                                && ((DelegateLDAPUserDetailsService) securityRealm.getSecurityComponents().userDetails).contains(this))
                               )
                        ) {
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
        @SuppressFBWarnings(value = "RCN_REDUNDANT_NULLCHECK_OF_NONNULL_VALUE", justification = "Only on newer core versions") //TODO remove when core is bumped
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
                final LDAPConfiguration configuration = ((LDAPSecurityRealm) realm).getConfigurationFor(details);
                String attr;
                if (configuration != null) {
                    attr = configuration.getMailAddressAttributeName();
                    if (StringUtils.isEmpty(attr)) {
                        attr = DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME;
                    }
                } else {
                    attr = DescriptorImpl.DEFAULT_MAILADDRESS_ATTRIBUTE_NAME;
                }
                Attribute mail = details.getAttributes().get(attr);
                if(mail==null)  return null;    // not found
                return (String)mail.get();
            } catch (DataAccessException | NamingException | AcegiSecurityException e) {
                LOGGER.log(Level.FINE, "Failed to look up LDAP for e-mail address",e);
                return null;
            }
        }
    }

    public static final class LdapAuthenticationProviderImpl extends LdapAuthenticationProvider {

        public LdapAuthenticationProviderImpl(LdapAuthenticator authenticator,
                                              LdapAuthoritiesPopulator authoritiesPopulator,
                                              LDAPGroupMembershipStrategy groupMembershipStrategy) {
            super(authenticator, groupMembershipStrategy != null
                    ? new WrappedAuthoritiesPopulator(groupMembershipStrategy, authoritiesPopulator)
                    : authoritiesPopulator);
        }
    }

    private static final class WrappedAuthoritiesPopulator implements LdapAuthoritiesPopulator {

        private final LDAPGroupMembershipStrategy strategy;
        private final LdapAuthoritiesPopulator populator;

        private WrappedAuthoritiesPopulator(LDAPGroupMembershipStrategy strategy, LdapAuthoritiesPopulator populator) {
            this.strategy = strategy;
            this.populator = populator;
            strategy.setAuthoritiesPopulator(populator);
        }

        @Override
        public GrantedAuthority[] getGrantedAuthorities(LdapUserDetails userDetails) throws LdapDataAccessException {
            if (strategy.getAuthoritiesPopulator() != populator) {
                strategy.setAuthoritiesPopulator(populator);
            }
            return strategy.getGrantedAuthorities(userDetails);
        }

    }

    /**
     * {@link LdapAuthoritiesPopulator} that adds the automatic 'authenticated' role.
     */
    public static final class AuthoritiesPopulatorImpl extends DefaultLdapAuthoritiesPopulator {
        // Make these available (private in parent class and no get methods!)
        String rolePrefix = "ROLE_";
        boolean convertToUpperCase = true;
        private GrantedAuthority defaultRole = null;

        public AuthoritiesPopulatorImpl(InitialDirContextFactory initialDirContextFactory, String groupSearchBase) {
            super(initialDirContextFactory, fixNull(groupSearchBase));

            super.setRolePrefix("");
            super.setConvertToUpperCase(false);
        }

        @Override
        public Set getAdditionalRoles(LdapUserDetails ldapUser) {
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

            if (isGeneratingPrefixRoles()) {
                for (GrantedAuthority ga : names) {
                    String role = ga.getAuthority();

                    // backward compatible name mangling
                    if (convertToUpperCase)
                        role = role.toUpperCase();
                    r.add(new GrantedAuthorityImpl(rolePrefix + role));
                }
            }

            return r;
        }

        public boolean isGeneratingPrefixRoles() {
            return StringUtils.isNotBlank(rolePrefix) || convertToUpperCase;
        }

        public boolean isConvertToUpperCase() {
            return convertToUpperCase;
        }

        public String getRolePrefix() {
            return rolePrefix;
        }

        public GrantedAuthority getDefaultRole() {
            return defaultRole;
        }

        public void setDefaultRole(String defaultRole) {
            // capture the default role in the event that legacy bean binding scripts are configuring it
            super.setDefaultRole(defaultRole);
            this.defaultRole = new GrantedAuthorityImpl(defaultRole);
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

        @Override
        public SecurityRealm newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            if (!formData.has("configurations")) {
                throw new Descriptor.FormException(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AtLeastOne(), "configurations");
            } else {
                final Object configurations = formData.get("configurations");
                if (configurations instanceof JSONArray) {
                    if (((JSONArray) configurations).isEmpty()) {
                        throw new Descriptor.FormException(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AtLeastOne(), "configurations");
                    } else if (((JSONArray) configurations).size() > 1) {
                        //check server names
                        List<LDAPConfiguration> confs = req.bindJSONToList(LDAPConfiguration.class, configurations);
                        for (int i = 0; i < confs.size(); i++) {
                            LDAPConfiguration ci = confs.get(i);
                            for (int k = i+1; k < confs.size(); k++) {
                                LDAPConfiguration ck = confs.get(k);
                                if (ci.isConfiguration(ck.getId())) {
                                    throw new Descriptor.FormException(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_NotSameServer(), "configurations");
                                }
                            }
                        }
                    }
                } else if (!(configurations instanceof JSONObject)) {
                    throw new Descriptor.FormException(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AtLeastOne(), "configurations");
                } else if (((JSONObject) configurations).isNullObject()) {
                    throw new Descriptor.FormException(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AtLeastOne(), "configurations");
                }
            }
            return super.newInstance(req, formData);
        }

        public boolean hasCustomBindScript() {
            return LDAPConfiguration.getLdapBindOverrideFile(Jenkins.getActiveInstance()).exists();
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
            return validate(realm, user, password);
        }

        private void rsp(StringBuilder response, String kind, String testId, String message, Object... extras) {
            response.append("<div class='").append(kind).append("' data-test='");
            response.append(Util.escape(testId));
            response.append("'>");
            response.append(message);
            boolean needBr = true;
            for (Object extra: extras) {
                if (extra instanceof String) {
                    if (needBr) {
                        response.append("<br/>");
                    }
                    response.append(extra);
                    needBr = true;
                } else if (extra instanceof Collection) {
                    response.append("<ul>");
                    for (String item : (Collection<String>)extra) {
                        response.append("<li>");
                        response.append(item);
                        response.append("</li>");
                    }
                    response.append("</ul>");
                    needBr = false;
                }
            }
            response.append("</div>");
        }

        private void ok(StringBuilder response, String testId, String message, Object... extras) {
            rsp(response, "validation-ok", testId, message, extras);
        }

        private void warning(StringBuilder response, String testId, String message, Object... extras) {
            rsp(response, "warning", testId, message, extras);
        }

        private void error(StringBuilder response, String testId, String message, Object... extras) {
            rsp(response, "error", testId, message, extras);
        }

        public FormValidation validate(LDAPSecurityRealm realm, String user, String password) {
            // we can only do deep validation if the connection is correct
            LDAPConfiguration.LDAPConfigurationDescriptor confDescriptor = Jenkins.getActiveInstance().getDescriptorByType(LDAPConfiguration.LDAPConfigurationDescriptor.class);
            for (LDAPConfiguration configuration : realm.getConfigurations()) {
                FormValidation connnectionCheck = confDescriptor.doCheckServer(configuration.getServerUrl(), configuration.getManagerDN(), configuration.getManagerPasswordSecret());
                if (connnectionCheck.kind != FormValidation.Kind.OK) {
                    return connnectionCheck;
                }
            }

            // ok let's start with authentication
            StringBuilder response = new StringBuilder(1024);
            response.append("<div>")
                    .append(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_LoginHeader())
                    .append("</div>");
            boolean potentialLockout = false;
            boolean likelyLockout = false;

            // can we login?
            LdapUserDetails loginDetails = null;
            try {
                // need to access direct so as not to update the user details
                loginDetails = (LdapUserDetails) realm.getSecurityComponents().manager.authenticate(
                        new UsernamePasswordAuthenticationToken(fixUsername(user), password)).getPrincipal();
                ok(response, "authentication",
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AuthenticationSuccessful());
            } catch (AuthenticationException e) {
                if (StringUtils.isBlank(password)) {
                    warning(response, "authentication",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AuthenticationFailedEmptyPass(user));
                } else {
                    error(response, "authentication",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AuthenticationFailed(user));
                    potentialLockout = true;
                    likelyLockout = true;
                }
            }
            Set<String> loginAuthorities = new HashSet<>();
            if (loginDetails != null) {
                // report details of the logged in user
                ok(response, "authentication-username",
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserId(Util.escape(loginDetails.getUsername())));
                ok(response, "authentication-dn",
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserDn(Util.escape(loginDetails.getDn())));
                LDAPConfiguration loginConfiguration = realm.getConfigurationFor(loginDetails);
                assert loginConfiguration != null;
                if (realm.hasMultiConfiguration()) {
                    ok(response, "authentication-configuration",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserConfiguration(Util.escape(loginConfiguration.getServer())));
                }
                validateDisplayName(loginConfiguration, response, loginDetails, "authentication-displayname");
                if (!realm.disableMailAddressResolver) {
                    validateEmailAddress(loginConfiguration, response, loginDetails, "authentication-email");
                }
                for (GrantedAuthority a : loginDetails.getAuthorities()) {
                    loginAuthorities.add(a.getAuthority());
                }
                if (loginDetails.getAuthorities().length < 1) {
                    error(response, "authentication-groups",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_NoGroupMembership());
                    // we do not flag this error as may be legitimate config
                } else if (loginDetails.getAuthorities().length == 1) {
                    warning(response, "authentication-groups",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_BasicGroupMembership(),
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_BasicGroupMembershipDetail());
                } else {
                    List<String> authorities = new ArrayList<>();
                    for (GrantedAuthority a : loginDetails.getAuthorities()) {
                        if (AUTHENTICATED_AUTHORITY.equals(a)) {
                            continue;
                        }
                        authorities.add("<code>"+ Util.escape(a.getAuthority()) + "</code>");
                    }
                    ok(response, "authentication-groups",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_GroupMembership(),
                            authorities);
                }
            }

            // can we lookup user by username?
            response.append("<div>")
                    .append(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_LookupHeader())
                    .append("</div>");
            LdapUserDetails lookUpDetails = null;
            try {
                // need to access direct so as not to update the user details
                lookUpDetails =
                        (LdapUserDetails) realm.getSecurityComponents().userDetails
                                .loadUserByUsername(fixUsername(user));
                ok(response, "lookup",
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserLookupSuccessful());
            } catch (UserMayOrMayNotExistException e1) {
                rsp(response, loginDetails == null ? "warning" : "error", "lookup",
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserLookupInconclusive(user),
                        isAnyManagerBlank(realm)
                                ? jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserLookupManagerDnRequired()
                                : jenkins.security.plugins.ldap.Messages
                                .LDAPSecurityRealm_UserLookupManagerDnPermissions()
                );
                // we do not flag these errors as could be probing user accounts
            } catch (UsernameNotFoundException e1) {
                rsp(response, loginDetails == null ? "warning" : "error", "lookup",
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserLookupDoesNotExist(user),
                        isAnyManagerBlank(realm)
                                ? jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserLookupManagerDnRequired()
                                : jenkins.security.plugins.ldap.Messages
                                .LDAPSecurityRealm_UserLookupManagerDnPermissions(),
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserLookupSettingsCorrect());
                // we do not flag these errors as could be probing user accounts
            } catch (LdapDataAccessException e) {
                Throwable cause = e.getCause();
                while (cause != null && !(cause instanceof BadCredentialsException)) {
                    cause = cause.getCause();
                }
                if (cause != null) {
                    error(response, "lookup",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserLookupBadCredentials(),
                            isAnyManagerBlank(realm)
                                    ? jenkins.security.plugins.ldap.Messages
                                    .LDAPSecurityRealm_UserLookupManagerDnCorrect()
                                    : jenkins.security.plugins.ldap.Messages
                                    .LDAPSecurityRealm_UserLookupManagerDnPermissions()
                    );
                    potentialLockout = true;
                } else {
                    error(response, "lookup",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserLookupFailed(user),
                            Util.escape(e.getLocalizedMessage()));
                    potentialLockout = true;
                }
            }
            if (loginDetails == null && lookUpDetails != null) {
                // we could not login, so let's report details of the resolved user
                ok(response, "lookup-username",
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserId(
                                Util.escape(lookUpDetails.getUsername())
                        ));
                ok(response, "lookup-dn",
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserDn(
                                Util.escape(lookUpDetails.getDn())
                        ));
                LDAPConfiguration lookupConfiguration = realm.getConfigurationFor(lookUpDetails);
                assert lookupConfiguration != null;
                if (realm.hasMultiConfiguration()) {
                    ok(response, "lookup-configuration",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserConfiguration(
                                    Util.escape(lookupConfiguration.getServer())
                            ));
                }
                validateDisplayName(lookupConfiguration, response, lookUpDetails, "lookup-displayname");
                if (!realm.disableMailAddressResolver) {
                    validateEmailAddress(lookupConfiguration, response, lookUpDetails, "lookup-email");
                }
            }
            Set<String> lookupAuthorities = new HashSet<>();
            if (lookUpDetails != null) {
                for (GrantedAuthority a : lookUpDetails.getAuthorities()) {
                    lookupAuthorities.add(a.getAuthority());
                }
                if (loginDetails == null || !loginAuthorities.equals(lookupAuthorities)) {
                    // report the group details if different or if we did not login
                    if (lookUpDetails.getAuthorities().length < 1) {
                        error(response, "lookup-groups",
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_NoGroupMembership());
                        // we do not flag this error as may be legitimate
                    } else if (lookUpDetails.getAuthorities().length == 1) {
                        warning(response, "lookup-groups",
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_BasicGroupMembership(),
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_BasicGroupMembershipDetail());
                    } else {
                        List<String> authorities = new ArrayList<>();
                        for (GrantedAuthority a : lookUpDetails.getAuthorities()) {
                            if (AUTHENTICATED_AUTHORITY.equals(a)) {
                                continue;
                            }
                            authorities.add("<code>" + Util.escape(a.getAuthority()) + "</code>");
                        }
                        ok(response, "lookup-groups",
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_GroupMembership(),
                                authorities);
                    }
                }
            }
            // let's check consistency
            if (loginDetails != null && lookUpDetails != null) {
                LDAPConfiguration loginConfiguration = realm.getConfigurationFor(loginDetails);
                LDAPConfiguration lookupConfiguration = realm.getConfigurationFor(lookUpDetails);
                assert loginConfiguration == lookupConfiguration : "The lookup user details and login user details are not from the same server configuration";
                // username
                if (!StringUtils.equals(loginDetails.getUsername(), lookUpDetails.getUsername())) {
                    error(response, "consistency-username",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UsernameMismatch(
                                    loginDetails.getUsername(), lookUpDetails.getUsername()));
                    potentialLockout = true; // consistency is important
                }
                // dn
                if (!StringUtils.equals(loginDetails.getDn(), lookUpDetails.getDn())) {
                    error(response, "consistency-dn",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_DnMismatch(
                                    loginDetails.getDn(), lookUpDetails.getDn()));
                    potentialLockout = true; // consistency is important
                }
                // display name
                if (StringUtils.isNotBlank(loginConfiguration.getDisplayNameAttributeName())) {
                    Attribute loginAttr = loginDetails.getAttributes().get(loginConfiguration.getDisplayNameAttributeName());
                    Object loginValue;
                    try {
                        loginValue = loginAttr == null ? null : loginAttr.get();
                    } catch (NamingException e) {
                        loginValue = e.getClass();
                    }
                    Attribute lookUpAttr = lookUpDetails.getAttributes().get(lookupConfiguration.getDisplayNameAttributeName());
                    Object lookUpValue;
                    try {
                        lookUpValue = lookUpAttr == null ? null : lookUpAttr.get();
                    } catch (NamingException e) {
                        lookUpValue = e.getClass();
                    }
                    if (loginValue == null ? lookUpValue != null : !loginValue.equals(lookUpValue)) {
                        error(response, "consistency-displayname",
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_DisplayNameMismatch(
                                        loginValue, lookUpValue));
                        potentialLockout = true; // consistency is important
                    }
                }
                // email address
                if (!realm.disableMailAddressResolver && StringUtils.isNotBlank(loginConfiguration.getMailAddressAttributeName()))
                {
                    Attribute loginAttr = loginDetails.getAttributes().get(loginConfiguration.getMailAddressAttributeName());
                    Object loginValue;
                    try {
                        loginValue = loginAttr == null ? null : loginAttr.get();
                    } catch (NamingException e) {
                        loginValue = e.getClass();
                    }
                    Attribute lookUpAttr = lookUpDetails.getAttributes().get(lookupConfiguration.getMailAddressAttributeName());
                    Object lookUpValue;
                    try {
                        lookUpValue = lookUpAttr == null ? null : lookUpAttr.get();
                    } catch (NamingException e) {
                        lookUpValue = e.getClass();
                    }
                    if (loginValue == null ? lookUpValue != null : !loginValue.equals(lookUpValue)) {
                        error(response, "consistency-email",
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_EmailAddressMismatch(
                                        loginValue, lookUpValue));
                        potentialLockout = true; // consistency is important
                    }
                }
                // groups
                if (loginAuthorities.equals(lookupAuthorities)) {
                    ok(response, "consistency",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_GroupMembershipMatch());
                } else {
                    error(response, "consistency",
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_GroupMembershipMismatch());
                    potentialLockout = true; // consistency is important
                }
            }
            // lets check group lookup if we can
            Set<String> groups = new HashSet<>(loginAuthorities);
            Set<String> badGroups = new TreeSet<>();
            groups.addAll(lookupAuthorities);
            groups.remove(AUTHENTICATED_AUTHORITY.getAuthority());
            for (String group : groups) {
                try {
                    realm.loadGroupByGroupname(group);
                } catch (UsernameNotFoundException e) {
                    badGroups.add(group);
                }
            }
            if (groups.isEmpty()) {
                warning(response, "resolve-groups",
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_GroupLookupNotPossible(),
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_GroupLookupNotPossibleDetail());
            } else if (badGroups.isEmpty()) {
                ok(response, "resolve-groups",
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_GroupLookupSuccessful(groups.size()));
            } else {
                List<String> escaped = new ArrayList<>(badGroups.size());
                for (String group : badGroups) {
                    escaped.add("<code>"+Util.escape(group)+"</code>");
                }
                warning(response, "resolve-groups",
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_GroupLookupFailed(badGroups.size()),
                        escaped,
                        isAnyManagerBlank(realm)
                                ? jenkins.security.plugins.ldap.Messages
                                .LDAPSecurityRealm_GroupLookupManagerDnRequired()
                                : jenkins.security.plugins.ldap.Messages
                                .LDAPSecurityRealm_GroupLookupManagerDnPermissions(),
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_GroupLookupSettingsCorrect());
            }
            if (potentialLockout) {
                response.append("<div>")
                        .append(jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_LockoutHeader())
                        .append("</div>");
                error(response, "lockout",
                        likelyLockout ? jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_PotentialLockout(user)
                                : jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_PotentialLockout2(user)
                );
            }
            // and we are done, report the results
            return FormValidation.okWithMarkup(response.toString());
        }

        private boolean isAnyManagerBlank(LDAPSecurityRealm realm) {
            for (LDAPConfiguration configuration : realm.getConfigurations()) {
                if (StringUtils.isBlank(configuration.getManagerDN())) {
                    return true;
                }
            }
            return false;
        }

        private void validateEmailAddress(LDAPConfiguration configuration, StringBuilder response,
                                          LdapUserDetails details, String testId) {
            Attribute attribute = details.getAttributes().get(configuration.getMailAddressAttributeName());
            if (attribute == null) {
                List<String> alternatives = new ArrayList<>();
                for (Attribute attr : Collections.list(details.getAttributes().getAll())) {
                    alternatives.add("<code>"+Util.escape(attr.getID())+"</code>");
                }
                warning(response, testId,
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_NoEmailAddress(),
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_IsAttributeNameCorrect(
                                Util.escape(configuration.getMailAddressAttributeName())
                        ),
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AvailableAttributes(),
                        alternatives);
            } else {
                try {
                    String mailAddress = (String) attribute.get();
                    if (StringUtils.isNotBlank(mailAddress)) {
                        ok(response, testId,
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserEmail(
                                        Util.escape(mailAddress)
                                ));
                    } else {
                        List<String> alternatives = new ArrayList<>();
                        for (Attribute attr : Collections.list(details.getAttributes().getAll())) {
                            alternatives.add("<code>" + Util.escape(attr.getID()) + "</code>");
                        }
                        warning(response, testId,
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_EmptyEmailAddress(),
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_IsAttributeNameCorrect(
                                        Util.escape(configuration.getMailAddressAttributeName())
                                ),
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AvailableAttributes(),
                                alternatives);
                    }
                } catch (NamingException e) {
                    List<String> alternatives = new ArrayList<>();
                    for (Attribute attr : Collections.list(details.getAttributes().getAll())) {
                        alternatives.add("<code>" + Util.escape(attr.getID()) + "</code>");
                    }
                    error(response, testId,
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_CouldNotRetrieveEmailAddress(),
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_IsAttributeNameCorrect(
                                    Util.escape(configuration.getMailAddressAttributeName())
                            ),
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AvailableAttributes(),
                            alternatives);
                }
            }
        }

        private void validateDisplayName(LDAPConfiguration configuration, StringBuilder response,
                                         LdapUserDetails details, String testId) {
            Attribute attribute = details.getAttributes().get(configuration.getDisplayNameAttributeName());
            if (attribute == null) {
                List<String> alternatives = new ArrayList<>();
                for (Attribute attr : Collections.list(details.getAttributes().getAll())) {
                    alternatives.add("<code>" + Util.escape(attr.getID()) + "</code>");
                }
                warning(response, testId,
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_NoDisplayName(),
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_IsAttributeNameCorrect(
                                Util.escape(configuration.getDisplayNameAttributeName())
                        ),
                        jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AvailableAttributes(),
                        alternatives);
            } else {
                try {
                    String displayName = (String) attribute.get();
                    if (displayName != null) {
                        ok(response, testId,
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_UserDisplayName(
                                        Util.escape(displayName)
                                ));
                    } else {
                        List<String> alternatives = new ArrayList<>();
                        for (Attribute attr : Collections.list(details.getAttributes().getAll())) {
                            alternatives.add("<code>" + Util.escape(attr.getID()) + "</code>");
                        }
                        warning(response, testId,
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_EmptyDisplayName(),
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_IsAttributeNameCorrect(
                                        Util.escape(configuration.getDisplayNameAttributeName())
                                ),
                                jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AvailableAttributes(),
                                alternatives);
                    }
                } catch (NamingException e) {
                    List<String> alternatives = new ArrayList<>();
                    for (Attribute attr : Collections.list(details.getAttributes().getAll())) {
                        alternatives.add("<code>" + Util.escape(attr.getID()) + "</code>");
                    }
                    error(response, testId,
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_CouldNotRetrieveDisplayName(),
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_IsAttributeNameCorrect(
                                    Util.escape(configuration.getDisplayNameAttributeName())
                            ),
                            jenkins.security.plugins.ldap.Messages.LDAPSecurityRealm_AvailableAttributes(),
                            alternatives);
                }
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

    @Restricted(NoExternalUse.class)
    public static final Logger LOGGER = Logger.getLogger(LDAPSecurityRealm.class.getName());

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
