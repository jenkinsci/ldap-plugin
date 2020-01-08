## Changelog

### Version 1.20 (19th Feb 2018)

-   [JENKINS-48917](https://issues.jenkins-ci.org/browse/JENKINS-48917):
    Add option to ignore specific LDAP domains in the event of a
    connection failure.
-   Add compatibility warning when upgrading from 1.15 or older due to
    configuration format changes in 1.16.

### Version 1.19 (31st Jan 2018)

-   [JENKINS-21784](https://issues.jenkins-ci.org/browse/JENKINS-21784):
    Add support for querying membership of LDAP groups.
-   Log communication failures with LDAP servers as warnings in the
    `hudson.security.LDAPSecurityRealm` logger.

### Version 1.18 (9th Nov 2017)

-   Upgrade to [new parent
    pom](https://github.com/jenkinsci/plugin-pom) (2.36).
-   Update test text to match UI
-   Updated baseline version of Jenkins to 1.651.3

### Version 1.17 (13th Sep 2017)

-   [JENKINS-45431](https://issues.jenkins-ci.org/browse/JENKINS-45431) Environment
    properties stopped working in 1.16

### Version 1.16 (3rd July 2017)

-   **[JENKINS-21475](https://issues.jenkins-ci.org/browse/JENKINS-21475) Added
    ability to configure multiple LDAP configurations to connect to LDAP
    servers with **different schemes etc.****
-   [JENKINS-43994](https://issues.jenkins-ci.org/browse/JENKINS-43994) When
    the user can login but lookup fails report this as a potential issue
    for API tokens and SSH key base authentication of the user.

### Version 1.15 (2nd May 2017)

-   Updated baseline version of Jenkins to 1.625.3
-   Added some tests that actually connect to an LDAP server to help
    prevent regressions
-   [JENKINS-21374](https://issues.jenkins-ci.org/browse/JENKINS-21374)
    Allow disabling ROLE\_ prefixed role creation
-   **[JENKINS-43388](https://issues.jenkins-ci.org/browse/JENKINS-43388)
    Added a validation button that allows for validation of the complete
    LDAP configuration**
    -   Fixed a bug in authorities population identified by the new
        validation button

### Version 1.14 (23rd Jan 2017)

-   Fixed
    [JENKINS-30588](https://issues.jenkins-ci.org/browse/JENKINS-30588):
    Value for "Group membership attribute" not saved.

### Version 1.13 (20th Sep 2016)

-   Fixed
    [JENKINS-8152](https://issues.jenkins-ci.org/browse/JENKINS-8152):
    The rootDN is now URI-encoded when included in the provider URL. If
    upgrading from previous versions, please take this into account if
    the value had been manually encoded.

### Version 1.12 (26th Apr 2016)

-   Upgrade to [new parent
    pom](https://github.com/jenkinsci/plugin-pom).
-   Integrate Findbugs and fix potential errors discovered by the
    plugin.

### Version 1.11 (3rd Oct 2014)

-   Performance improvements especially in the presence of lots of
    requests with HTTP basic auth.

### Version 1.10.2 (23rd May 2014)

-   Fixed another NPE in FromUserRecordLDAPGroupMembershipStrategy

### Version 1.10.1 (23rd May 2014)

-   Fixed NPE in FromUserRecordLDAPGroupMembershipStrategy.

### Version 1.10 (22nd May 2014)

-   Turned the group membership lookup into a strategy. There are now
    two strategies, the default "look up groups containing the user"
    strategy and an experimental new strategy which looks for an
    attribute in the user's LDAP record that contains a list of DNs of
    the groups that the user belongs to. **Rumour has it that this
    second strategy may actually provide faster performance for Active
    Directory, but as the person who wrote this code does not have an
    Active Directory instance to test against - until some kind soul
    tests, confirms and edits this text to remove the assertion that
    this is a rumour - using the new strategy is** ***Caveat
    emptor*****.**

**\[Update 23/05/2014\] Some kind testers have confirmed that the new
strategy seems to work against Active Directory... but as those testers
did not have performance issues to start with, again it is just a rumour
that there is a performance increase! Version 1.10.2 is recommended to
fix two non-critical but annoying NPEs with the new strategy**

### Version 1.9 (9th May 2014)

-   Added some interim hacks to work around
    [JENKINS-22247](https://issues.jenkins-ci.org/browse/JENKINS-22247).
    Setting the temporary system properties 

        hudson.security.LDAPSecurityRealm.forceUsernameLowercase=true

    and 

        hudson.security.LDAPSecurityRealm.forceGroupnameLowercase=true

    will enable these hacks. These system properties will be removed in
    a future version once the core issue has been resolved.

-   Modernised the configuration screen Jelly to use current
    form-binding.
-   The manager password is now correctly encrypted using Secret. This
    is a downgrade breaking change. **WARNING! If you upgrade to 1.9 and
    then downgrade, the manager password may be lost from your
    configuration. **

### Version 1.8 (17th Jan 2014)

-   Fixed
    [JENKINS-18355](https://issues.jenkins-ci.org/browse/JENKINS-18355)

### Version 1.7 (9th Dec 2013)

-   Fixed
    [JENKINS-16443](https://issues.jenkins-ci.org/browse/JENKINS-16443)
-   Add ability to define LDAP environment properties.

### Version 1.6 (24th Jul 2013)

-   Add support for multiple servers.

### Version 1.5 (14th Jun 2013)

-   Add readme.
-   Fixed
    [JENKINS-17281](https://issues.jenkins-ci.org/browse/JENKINS-17281)

### Version 1.4 (24th Apr 2013)

-   Move userDetails caching into the user details service to avoid
    callers bypassing the cache.

### Version 1.3 (24th Apr 2013)

-   Add Chinese (traditional) translation.
-   Update .gitignore.
-   Add an optional caching mechanism for loadByUsername and
    loadGroupByGroupName.

### Version 1.2 (6th Dev 2012)

-   Added .gitignore.
-   Update Surefire version.
-   Add "Disable Ldap Mail Resolver" checkbox/functionality.

### Version 1.1 (11th Jun 2012)

-   Explicitly set the classloader so that classes in the plugin do not
    fail to resolve.
-   Complete pom.xml.

### Version 1.0 (6th Jun 2012)

-   Initial release.
