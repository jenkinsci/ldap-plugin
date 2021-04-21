Jenkins LDAP Plugin
===================

*Note*: This plugin was part of the Jenkins core until 1.468. After
that, it was split out into a separately-updateable plugin. However, for
backwards compatibility purposes, subsequent core releases still bundle
it. If you do not use this plugin at all, you can simply disable it.

## Description

This plugin provides yet another way of authenticating users using LDAP.
It can be used with LDAP servers like Active Directory or OpenLDAP among
others. Supported configuration can be found below these lines. 

### Compatibility Notes

Various LDAP servers use different operational attributes to make decisions on
and expose configurations of concepts such as disabling an account, locking an
account, and specifying a time interval the account is valid for. These policies
are normally enforced by the LDAP server itself when performing user authentication.
Jenkins provides alternative authentication mechanisms (such as API tokens and SSH
keys) that do not perform LDAP authentication directly; instead, Jenkins checks the
user details attributes for whether the user is enabled, locked, or expired.
These user attributes are specified by
[**slapo-ppolicy**(5)](https://linux.die.net/man/5/slapo-ppolicy) from OpenLDAP,
Active Directory Application Mode (ADAM), classic Active Directory, and eDirectory LDAP.
The support of these features is entirely dependent upon the LDAP server implementation
properly exposing these operational attributes which is dependent on the exact version
and distribution of the LDAP server in use. Being operational attributes, these are not
always exposed by LDAP server implementations to clients the same way as they may be
used internally. 

#### Administratively Disabled Accounts

Accounts that are disabled by administrators typically expose an operational attribute
to indicate such. The following attributes are all supported:

* `pwdAccountLockedTime` value of `000001010000Z`: common LDAP attribute using password policy overlay;
* `msDS-UserAccountDisabled` value of `TRUE`: modern [Active Directory attribute](https://docs.microsoft.com/en-us/windows/win32/adschema/a-msds-useraccountdisabled);
* `userAccountControl` (UAC) or `msDS-User-Account-Control-Computed` with bit flag of `ADS_UF_ACCOUNTDISABLE` (0x2) present; and
* `loginDisabled` value of `TRUE`: eDirectory attribute.

#### Expired Accounts

Accounts can have a specific start or end time associated with when the account can be
authenticated. This feature allows administrators to automate account start and termination
dates without having to manually disable or delete accounts. The following attributes support this:

* `pwdStartTime` timestamp in the future, or `pwdEndTime` timestamp in the past (LDAP password policy);
* `accountExpires` timestamp in the past (Active Directory); and
* `loginExpirationTime` timestamp in the past (eDirectory).

Note that while these timestamps all include timezone information, they are compared against
the Jenkins system clock.

#### Password Expiration

Active Directory provides some attributes to indicate that an account has expired credentials.
The boolean attribute `msDS-UserPasswordExpired` (ADAM) or the UAC flag `ADS_UF_PASSWORD_EXPIRED`
are checked.

#### Locked Accounts

Accounts can be locked by intruder detection systems. The following attributes support this:

* `pwdLockout` value of `TRUE`: LDAP password policy;
* UAC flag `ADS_UF_LOCK_OUT` (0x10) is present (Active Directory); and
* `lockedByIntruder` value of `TRUE` (eDirectory).

## Configuration

Select LDAP for the Security Realm. You will most likely need to
configure some of the Advanced options. There is on-line help available
for each option. 
![](/docs/images/Screen_Shot_2017-05-02_at_09.52.20.png)

### Server

Specify the name of the LDAP server host name (like `ldap.acme.org`).

If your LDAP server uses a port other than `389` (which is the standard
for LDAP), you can also append a port number here, like
`ldap.acme.org:1389`.

To connect to LDAP over SSL (AKA LDAPS), specify it with the `ldaps://`
protocol, like `ldaps://ldap.acme.org` or `ldaps://ldap.acme.org:1636`
(if the port is other than the default `636`).

As of version 1.6, you can specify a list of servers separated by
whitespace to provide a fallback if the first server is unavailable,
e.g. `ldap1.acme.org ldap2.acme.org:1389` or
`ldaps://ldap1.acme.org:1636 ldap1.acme.org:1389 ldap://ldap2.acme.org ldap3.acme.org`

### Test LDAP Settings

This button will allow you to check the full LDAP configuration settings
which you have defined (as compared with the field validation which only
verifies a subset of the configuration)

Clicking this button will display a modal dialog to prompt you to
provide a username and password:

![](/docs/images/test-ldap-dialog.png)

There are a number of tests that you should perform before saving a new
/ modified security configuration:

-   Enter your own username & password to validate that you will still
    be able to login after the security settings have been applied =\>
    *You do not want to lock yourself out*
-   Ideally get a couple of other users to try their username & password
    to ensure that other users can login. If you cannot get other users
    to come to your computer, you can at least verify that Jenkins can
    resolve their accounts by using their username and an empty password
    =\> *You do not want to lock legitimate users out*
-   In most cases, you will be using LDAP groups, so ensure that you
    verify reverse group lookup by testing with a user account that is a
    member of at least one group (do not forget the empty password trick
    to perform lookup). If there are important groups for your Jenkins
    instance, try using at least one user for each important group =\>
    You want to ensure that group lookup functions correctly.

:warning:
**NOTE** it is quite likely that existing
installations may have subtle issues with group resolution, it is
recommended that you validate your group resolution with the new button
functionality after upgrading the LDAP plugin to 1.15 as there is a good
chance that it will catch problems you didn't really know you had!

### Root DN

For authenticating user and determining the roles given to this user,
Jenkins performs multiple LDAP queries.

Since an LDAP database is conceptually a big tree and the search is
performed recursively, in theory if we can start a search starting at a
sub-node (as opposed to root), you get a better performance because it
narrows down the scope of a search.

This field specifies the DN of such a subtree.

But in practice, LDAP servers maintain an extensive index over the data,
so specifying this field is rarely necessary — you should just let
Jenkins figure this out by talking to LDAP.

If you do specify this value, the field normally looks something like
`dc=acme,dc=org`

### User search base

One of the searches Jenkins does on LDAP is to locate the user record
given the user name.

If you specify a relative DN (from the root DN) here, Jenkins will
further narrow down searches to the sub-tree.

But in practice, LDAP servers maintain an extensive index over the data,
so specifying this field is rarely necessary.

If you do specify this value, the field normally looks something like
`ou=people`

### User search filter

One of the searches Jenkins does on LDAP is to locate the user record
given the user name.

 This field determines the query to be run to identify the user record.

The query is almost always `uid={0}` as per defined in RFC 2798, so in
most cases you should leave this field empty and let this default kick
in.

If your LDAP server doesn't have `uid` or doesn't use a meaningful `uid`
value, try `mail={0}`, which lets people login by their e-mail address.

If you do specify a different query, specify an LDAP query string with
marker token {`0`}, which is to be replaced by the user name string
entered by the user.

### Group search base

One of the searches Jenkins does on LDAP is to locate the list of groups
for a user.

This field determines the query to be run to identify the organizational
unit that contains groups.

The query is almost always `ou=groups` so try that first, though this
field may be left blank to search from the root DN.

If login attempts result in "Administrative Limit Exceeded" or similar
error, try to make this setting as specific as possible for your LDAP
structure, to reduce the scope of the query.

If the error persists, you may need to change the Group membership
filter from the default of
`(| (member={0}) (uniqueMember={0}) (memberUid={1}))` to a query only of
the field used in your LDAP for group membership, such as:
`(member={0})`.

You will need to login and logout in order to verify that your group
membership is retained with a modified group membership filter.

### Group search filter

When Jenkins is asked to determine if a named group exists, it uses a
default filter of:  
`(& (cn={0}) (| (objectclass=groupOfNames) (objectclass=groupOfUniqueNames) (objectclass=posixGroup)))`

relative to the Group search base to determine if there is a group with
the specified name ({`0`} is substituted by the name being searched
for.)

If you know your LDAP server only stores group information in one
specific object class, then you can improve group search performance by
restricting the filter to just the required object class.

Note: if you are using the LDAP security realm to connect to Active
Directory (as opposed to using the Active Directory plugin's security
realm) then you will need to change this filter to:  
`(& (cn={0}) (objectclass=group) )`

Note: if you leave this empty, the default search filter will be used.

### Group membership

When Jenkins resolves a user, the next step in the resolution process is
to determine the LDAP groups that the user belongs to.

There is an extension point for providing a strategy to resolve the LDAP
groups that the user belongs to. There are two implementations provided
in the LDAP plugin:

-   Search for groups containing user (default)
-   Parse user attribute for list of groups

#### Search for groups containing user

![](/docs/images/Screen_Shot_2014-07-15_at_10.19.23.png)

The group membership filter field controls the search filter that is
used to determine group membership.

If left blank, the default filter will be used. The default default
filter is: `(| (member={0}) (uniqueMember={0}) (memberUid={1}))`.
Irrespective of what the default is, setting this filter to a non-blank
value will determine the filter used.

You are normally safe leaving this field unchanged, however for large
LDAP servers where you are seeing messages such as
"OperationNotSupportedException - Function Not Implemented",
"Administrative Limit Exceeded" or similar periodically when trying to
login, then that would indicate that you should change to a more optimum
filter for your LDAP server, namely one that queries only the required
field, such as: `(member={0})`

The LDAP server may be able to use query hints to optimize the search.
For example:

-   If all the groups you are interested in are within a specific
    subtree, adding the subtree information to the filter should improve
    performance.

-   Active Directory's query optimizer can make significant
    optimizations if it knows that the object category is
    group: `(&(objectCategory=group)(member={0}))` this may be relevant
    if using Active Directory's matching rule in chain extension, e.g.
    `(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:={0}))`

Note: in this field there are two available substitutions:  
{`0`} - the fully qualified DN of the user  
{`1`} - the username portion of the user

#### Parse user attribute for list of groups

![](/docs/images/Screen_Shot_2014-07-15_at_10.19.14.png)  
Some LDAP servers can provide a `memberOf` attribute within the User's
record:

-   Active Directory
-   OpenLDAP with the [memberof
    overlay](http://www.openldap.org/doc/admin24/overlays.html#Reverse%20Group%20Membership%20Maintenance)
    active (untested, and as memberof is an operational attribute in
    OpenLDAP it must be explicitly requested, so may or may not work)
-   (If you know of others please provide details here)

This attribute can be used to simplify the group search and return the
group membership immediately without a second LDAP query. Note, however,
that this may result in only direct group membership being supported.

The `group membership attribute field` controls the attribute name that
is used to determine the groups to which a user belongs.

### Manager DN and Manager Password

If your LDAP server doesn't support anonymous binding (IOW, if your LDAP
server doesn't even allow a query without authentication), then Jenkins
would have to first authenticate itself against the LDAP server, and
Jenkins does that by sending "manager" DN and password.

A DN typically looks like `CN=MyUser,CN=Users,DC=mydomain,DC=com`
although the exact sequence of tokens depends on the LDAP server
configuration.

It can be any valid DN as long as LDAP allows this user to query data.

This configuration is also useful when you are connecting to Active
Directory from a Unix machine, as AD doesn't allow anonymous bind by
default. But if you can't figure this out, you can also change AD
setting to allow anonymous bind. 

### Disable LDAP Email resolver

Controls whether LDAP will be used to try and resolve the email
addresses of users.

### Enable cache

Some LDAP servers may be slow, or rate limit client requests.

In such cases enabling caching may improve performance of Jenkins with
the risk of delayed propagation of user changes from LDAP and increased
memory usage on the Jenkins controller.

Note: The default configuration is to leave the cache turned off.

### Environment Properties

As of 1.7 of the LDAP plugin, you can now specify additional Environment
properties to provide the backing Java LDAP client API. See [Oracle's
documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jndi/jndi-ldap.html) for
details of what properties are available and what functionality they
provide. As a minimum you should strongly consider providing the
following

| Property Name                       | Description                                                                                                                                                                                                                                                                                                 |
|-------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `com.sun.jndi.ldap.connect.timeout` | This is the socket connection timeout in milliseconds. If your LDAP servers are all close to your Jenkins server you can probably set a small value, e.g. 5000 milliseconds. Setting a value smaller that this may result in excessive timeouts due to the TCP/IP connection establishment retry mechanism. |
| `com.sun.jndi.ldap.read.timeout`    | This is the socket read timeout in milliseconds. If your LDAP queries are all fast you can probably set a low value. A reasonable default is 60000 milliseconds.                                                                         |

## Troubleshooting

The following [Groovy
script](https://wiki.jenkins-ci.org/display/JENKINS/Jenkins+Script+Console)
can be useful when trying to determine whether you have group search
configured correctly:

``` java
    String[] names = ["a group name","a user name","a name that does not exist"];
    for (name in names) {
      println("Checking the name '" + name + "'...")
      try {
        println("  It is a USER: " + Jenkins.instance.securityRealm.loadUserByUsername(name))
        println("  Has groups/authorities: " + Jenkins.instance.securityRealm.loadUserByUsername(name).getAuthorities())
      } catch (Exception e) {
          try {
            println("  It is a GROUP: " + Jenkins.instance.securityRealm.loadGroupByGroupname(name))
            println("")
            continue
          } catch (Exception e1) {
            println("  It is NOT a group, reason: " + e1.getMessage())
          }
        println("  It is NOT a user, reason: " + e.getMessage())
      }
      println("");
    }
```

-   If login attempts result in "OperationNotSupportedException -
    Function Not Implemented", "Administrative Limit Exceeded" or
    similar error, the LDAP query to determine the group membership for
    the user may be triggering this. First try setting the "Group search
    base" setting as specific as possible for your LDAP structure, to
    reduce the scope of the query. If the error persists, you may need
    to customize the **Group search filter**. Change the filter
    to query only of the field used in your LDAP for group membership,
    such as `groupSearchFilter = "(member={0})";` (then restart
    Jenkins).
-   The LDAP groups were available in Jenkins in the format of
    ROLE\_Uppercasedgroupname, so the developers ldap group would be
    ROLE\_Developers in Jenkins, but since 1.404 they are available as
    is: no prefix or upper casing,
    by checking **Disable Backward Compatibility for Roles**.
-   If you are using this plugin and not the [Active Directory
    plugin](https://wiki.jenkins.io/display/JENKINS/Active+Directory+plugin) to
    connect to Active Directory, you will need to change the Group
    Search Filter to filter to: `(& (cn={0}) (objectclass=group) )` and
    change the Group Membership Filter to: `(member={0})`. If you want
    AD to return nested group membership then change the Group
    Membership Filter to: `(member:1.2.840.113556.1.4.1941:={0})`

## Performance Tuning

Here is a checklist to help improve performance:

-   Ensure you are using the very latest version of the LDAP plugin
-   Ensure you have enabled caching. Start with the cache size to just
    greater than your anticipated maximum concurrent users and set the
    TTL to the longest time interval you are comfortable with... (i.e.
    how long before a password change gets picked up... in most cases 5
    or 10 minutes is a good TTL)

Those two changes should give you an immediate significant performance
boost (even with a TTL of 30s as long as the cache size is larger than
max anticipated concurrent users... but a longer TTL is better)

-   Next up is to ensure that you have got the correct most specific
    `user search base` and `group search base` defined for your LDAP
    tree. Getting this right has two side-effects... you get faster
    results to your queries; and your LDAP server admin people will
    thank you for reducing the load on their server by a significant
    amount.
-   Finally, you should ensure that you have defined specific queries
    for the `user search filter` and `group search filter`... the user
    one is usually fine as is... the group one is, by default, a
    combination of typical queries. A significant performance
    improvement can be achieved by switching from the default `or`
    filter of
    `(& (cn={0}) (| (objectclass=groupOfNames) (objectclass=groupOfUniqueNames) (objectclass=posixGroup)))`
    to the correct for your LDAP tree query, i.e. it would be one of
    `(& (cn={0}) (objectclass=groupOfNames))`,`(& (cn={0}) (objectclass=groupOfUniqueNames))`
    or `(& (cn={0}) (objectclass=posixGroup))`. (...and if it is not one
    of them then your LDAP server is most likely Active Directory and
    Kohsuke makes me ask why you are using the LDAP plugin and not the
    Active Directory plugin in that case! Note that
    [JENKINS-16429](https://issues.jenkins-ci.org/browse/JENKINS-16429)
    might be a good reason to favour the LDAP plugin over the Active
    Directory plugin, but if that issue is resolved by the time you are
    reading this then there should be no reason to pick the LDAP plugin
    over the Active Directory plugin)

### Tips and Tricks

If you are using the LDAP plugin to connect to Active Directory you
should probably read this page of [AD syntax
notes](http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx).
Pay special attention to Notes 10 and 19. The following settings are
reported to work with Active Directory and nested groups, though they
should carry a warning that they may impact login performance and they
have not been tested for completeness:

-   User search filter: `sAMAccountName={0}`
-   Group search filter: `(&(objectclass=group)(cn={0}))`
-   Group membership, one of
    -   *Search for groups containing user* (if nested group membership
        required)
        -   Group membership
            filter: `(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:={0}))`
    -   *Parse user attribute for list of groups* (if nested group
        membership not required this will be faster)
        -    Group membership attribute: `memberOf`

Additionally, If you are using the `/` character in the name of some `Organization Unit` 
and some of your users or groups are located inside this `Organization Unit`
you can face some authentication trouble due to how Java8 treat the `principalDN`.
You will know you will face this issue because you can see the following exception 
in the Jenkins logs:

```
Caused by: org.acegisecurity.ldap.LdapDataAccessException: 
Unable to get first element; nested exception is javax.naming.InvalidNameException: Invalid name: "XXXXXXX / XXXXXXX",dc=example,dc=org
```  

For avoid this kind of authentication error you shouldn't use `/` character in the
name of any `Organization Unit` that is used for containing users or groups. 


Development
===========

Start the local Jenkins instance:

    mvn hpi:run


How to install
--------------

Run

	mvn clean package

to create the plugin .hpi file.


To install:

1. copy the resulting ./target/ldap.hpi file to the $JENKINS_HOME/plugins directory. Don't forget to restart Jenkins afterwards.

2. or use the plugin management console (http://example.com:8080/pluginManager/advanced) to upload the hpi file. You have to restart Jenkins in order to find the plugin in the installed plugins list.


Configuration with JCasC
---------------

```yaml
jenkins:
  securityRealm:
    ldap:
      configurations:
        - server: ldap.acme.com
          rootDN: dc=acme,dc=fr
          managerDN: "manager"
          managerPasswordSecret: ${LDAP_PASSWORD}
          userSearch: "(&(objectCategory=User)(sAMAccountName={0}))"
          groupSearchFilter: "(&(cn={0})(objectclass=group))"
          groupMembershipStrategy:
            fromGroupSearch:
              filter: "(&(objectClass=group)(|(cn=GROUP_1)(cn=GROUP_2)))"
      cache:
        size: 100
        ttl: 10
      userIdStrategy: CaseInsensitive
      groupIdStrategy: CaseSensitive
```
To get more examples, see [yaml files used in tests](src/test/resources/jenkins/security/plugins/ldap)

Plugin releases
---------------

	mvn release:prepare release:perform -B


License
-------

	(The MIT License)

    Copyright (c) 2004-2013, Sun Microsystems, Inc., Kohsuke Kawaguchi, Seiji Sogabe,
       Olivier Lamy, CloudBees, Inc., Stephen Connolly, and others

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
