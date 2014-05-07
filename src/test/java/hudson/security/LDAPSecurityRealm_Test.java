/*
 * The MIT License
 *
 * Copyright 2014 Jesse Glick.
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

import java.util.Collections;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

public class LDAPSecurityRealm_Test { // different name so as not to clash with LDAPSecurityRealmTest.groovy

    @Rule public JenkinsRule r = new JenkinsRule();

    @LocalData
    @Test public void compatAndConfig() throws Exception {
        check();
        r.configRoundtrip();
        check();
    }

    private void check() {
        LDAPSecurityRealm sr = (LDAPSecurityRealm) r.jenkins.getSecurityRealm();
        assertEquals("s", sr.server);
        assertEquals("rDN", sr.rootDN);
        assertEquals("uSB", sr.userSearchBase);
        assertEquals("uS", sr.userSearch);
        assertEquals("gSB", sr.groupSearchBase);
        assertEquals("gSF", sr.groupSearchFilter);
        assertEquals("gMF", sr.groupMembershipFilter);
        assertEquals("mDN", sr.managerDN);
        assertEquals("s3cr3t", sr.getManagerPassword());
        assertTrue(sr.inhibitInferRootDN);
        assertTrue(sr.disableMailAddressResolver);
        assertEquals(Integer.valueOf(20), sr.getCacheSize());
        assertEquals(Integer.valueOf(60), sr.getCacheTTL());
        assertEquals(Collections.singletonMap("k", "v"), sr.getExtraEnvVars());
        assertEquals("dNAN", sr.getDisplayNameAttributeName());
        assertEquals("mAAN", sr.getMailAddressAttributeName());
    }

}
