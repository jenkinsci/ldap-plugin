Jenkins LDAP Plugin
===================

Read more: [https://wiki.jenkins-ci.org/display/JENKINS/LDAP+Plugin](https://wiki.jenkins-ci.org/display/JENKINS/LDAP+Plugin)

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
