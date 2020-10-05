/*
 * The MIT License
 *
 * Copyright (c) 2019, CloudBees, Inc.
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

import net.time4j.Moment;
import net.time4j.PlainDate;
import net.time4j.PlainTime;
import net.time4j.format.DisplayMode;
import net.time4j.format.expert.ChronoFormatter;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Ease all the computations required to determine the user account optional attributes for creating
 * the UserDetails that will be used by the SecurityRealm
 */
@Restricted(NoExternalUse.class)
public class UserAttributesHelper {
    private static final Logger LOGGER = LDAPSecurityRealm.LOGGER;
    // https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro
    private static final String ATTR_USER_ACCOUNT_CONTROL = "userAccountControl";
    private static final String ATTR_ACCOUNT_EXPIRES = "accountExpires";
    // https://ldapwiki.com/wiki/Draft-behera-ldap-password-policy
    private static final String ATTR_LOGIN_DISABLED = "loginDisabled";
    private static final String ATTR_ORACLE_IS_ENABLED = "orclIsEnabled";
    private static final String ATTR_PWD_ACCOUNT_LOCKED_TIME = "pwdAccountLockedTime";
    private static final String ATTR_PWD_START_TIME = "pwdStartTime";
    private static final String ATTR_PWD_END_TIME = "pwdEndTime";
    private static final String ATTR_LOGIN_EXPIRATION_TIME = "loginExpirationTime";
    private static final String ATTR_PWD_LOCKOUT = "pwdLockout";
    private static final String ATTR_LOGIN_INTRUDER_RESET_TIME = "loginIntruderResetTime";
    // for Windows Server 2003-based domain
    private static final String ATTR_USER_ACCOUNT_CONTROL_COMPUTED = "msDS-User-Account-Control-Computed";
    // for ADAM (Active Directory Application Mode), replace the ADS_UF_DISABLED
    private static final String ATTR_USER_ACCOUNT_DISABLED = "msDS-UserAccountDisabled";
    // for ADAM, replace the ADS_UF_PASSWORD_EXPIRED
    private static final String ATTR_USER_PASSWORD_EXPIRED = "msDS-UserPasswordExpired";
    private static final String ACCOUNT_DISABLED = "000001010000Z"; // other GeneralizedTime values indicate account is locked as of that time

    // https://docs.microsoft.com/en-us/windows/desktop/adschema/a-accountexpires
    // constant names follow the code in Iads.h
    private static final long ACCOUNT_NO_EXPIRATION = 0x7FFF_FFFF_FFFF_FFFFL;
    private static final int ADS_UF_DISABLED = 0x0002;
    private static final int ADS_UF_LOCK_OUT = 0x0010;
    private static final int ADS_DONT_EXPIRE_PASSWORD = 0x1_0000;
    private static final int ADS_UF_PASSWORD_EXPIRED = 0x80_0000;

    private static final ChronoFormatter<Moment> GENERALIZED_TIME_FORMATTER;

    static {
        // https://stackoverflow.com/a/42383153
        // this static block licensed https://creativecommons.org/licenses/by-sa/3.0/
        ChronoFormatter<PlainDate> df =
                ChronoFormatter.setUp(PlainDate.axis(), Locale.ROOT)
                        .addFixedInteger(PlainDate.YEAR, 4)
                        .addFixedInteger(PlainDate.MONTH_AS_NUMBER, 2)
                        .addFixedInteger(PlainDate.DAY_OF_MONTH, 2)
                        .build();
        GENERALIZED_TIME_FORMATTER =
                ChronoFormatter.setUp(Moment.axis(), Locale.US) // US for preference of dot in decimal elements
                        .addCustomized(PlainDate.COMPONENT, df)
                        .addFixedInteger(PlainTime.DIGITAL_HOUR_OF_DAY, 2)
                        .startOptionalSection()
                        .addFixedInteger(PlainTime.MINUTE_OF_HOUR, 2)
                        .startOptionalSection()
                        .addFixedInteger(PlainTime.SECOND_OF_MINUTE, 2)
                        .startOptionalSection()
                        .addLiteral('.', ',')
                        .addFraction(PlainTime.NANO_OF_SECOND, 1, 9, false)
                        .endSection()
                        .endSection()
                        .endSection()
                        .addTimezoneOffset(DisplayMode.SHORT, false, Collections.singletonList("Z"))
                        .or()
                        .addCustomized(PlainDate.COMPONENT, df)
                        .addFixedInteger(PlainTime.DIGITAL_HOUR_OF_DAY, 2)
                        .addFixedDecimal(PlainTime.DECIMAL_MINUTE)
                        .addTimezoneOffset(DisplayMode.SHORT, false, Collections.singletonList("Z"))
                        .or()
                        .addCustomized(PlainDate.COMPONENT, df)
                        .addFixedDecimal(PlainTime.DECIMAL_HOUR)
                        .addTimezoneOffset(DisplayMode.SHORT, false, Collections.singletonList("Z"))
                        .build();
    }

    // https://ldapwiki.com/wiki/Administratively%20Disabled
    public static boolean checkIfUserIsEnabled(@Nonnull Attributes user) {
        // Active Directory attributes
        Integer uac = getUserAccountControl(user);
        if (uac != null && (uac & ADS_UF_DISABLED) == ADS_UF_DISABLED) {
            return false;
        }
        Boolean accountDisabled = getBooleanAttribute(user, ATTR_USER_ACCOUNT_DISABLED);
        if (accountDisabled != null) {
            return !accountDisabled;
        }
        // (Internet Draft) LDAP password policy attributes
        if (ACCOUNT_DISABLED.equals(getStringAttribute(user, ATTR_PWD_ACCOUNT_LOCKED_TIME))) {
            return false;
        }
        // EDirectory attributes
        Boolean loginDisabled = getBooleanAttribute(user, ATTR_LOGIN_DISABLED);
        if (loginDisabled != null) {
            return !loginDisabled;
        }
        // Oracle attributes
        String oracleIsEnabled = getStringAttribute(user, ATTR_ORACLE_IS_ENABLED);
        if (oracleIsEnabled != null) {
            switch (oracleIsEnabled.toUpperCase(Locale.ENGLISH)) {
                case "ENABLED": return true;
                case "DISABLED": return false;
                default: break;
            }
        }
        // no other indicators
        return true;
    }

    // https://ldapwiki.com/wiki/Account%20Expiration
    public static boolean checkIfAccountNonExpired(@Nonnull Attributes user) {
        // Active Directory attributes
        String accountExpirationDate = getStringAttribute(user, ATTR_ACCOUNT_EXPIRES);
        if (accountExpirationDate != null) {
            long expirationAsLong = Long.parseLong(accountExpirationDate);
            if (expirationAsLong == 0L || expirationAsLong == ACCOUNT_NO_EXPIRATION) {
                return true;
            }

            long nowIn100NsFromJan1601 = getWin32EpochHundredNanos();
            return expirationAsLong > nowIn100NsFromJan1601;
        }
        Moment now = Moment.nowInSystemTime();
        // (Internet Draft) LDAP password policy attributes
        Moment startTime = getGeneralizedTimeAttribute(user, ATTR_PWD_START_TIME);
        if (startTime != null && startTime.isBefore(now)) {
            return false;
        }
        Moment endTime = getGeneralizedTimeAttribute(user, ATTR_PWD_END_TIME);
        if (endTime != null) {
            return endTime.isAfter(now);
        }
        // EDirectory attributes
        Moment loginExpirationTime = getGeneralizedTimeAttribute(user, ATTR_LOGIN_EXPIRATION_TIME);
        if (loginExpirationTime != null) {
            return loginExpirationTime.isAfter(now);
        }
        // no other indicators
        return true;
    }

    // documentation: https://docs.microsoft.com/en-us/windows/desktop/adschema/a-accountexpires
    // code inspired by https://community.oracle.com/thread/1157460
    private static long getWin32EpochHundredNanos() {
        GregorianCalendar win32Epoch = new GregorianCalendar(1601, Calendar.JANUARY, 1);
        Date win32EpochDate = win32Epoch.getTime();
        // note that 1/1/1601 will be returned as a negative value by Java
        GregorianCalendar today = new GregorianCalendar();
        Date todayDate = today.getTime();
        long timeSinceWin32EpochInMs = todayDate.getTime() - win32EpochDate.getTime();
        // milliseconds to microseconds => x1000
        long timeSinceWin32EpochInNs = TimeUnit.NANOSECONDS.convert(timeSinceWin32EpochInMs, TimeUnit.MILLISECONDS);
        // but we need in 100 ns, as 1000 ns = 1 micro, add a x10 factor
        return timeSinceWin32EpochInNs * 100;
    }

    // https://ldapwiki.com/wiki/Password%20Expiration
    public static boolean checkIfCredentialsAreNonExpired(@Nonnull Attributes user) {
        // Active Directory attributes
        Integer uac = getUserAccountControl(user);
        if (uac != null) {
            if ((uac & ADS_DONT_EXPIRE_PASSWORD) == ADS_DONT_EXPIRE_PASSWORD) {
                return true;
            }
            if ((uac & ADS_UF_PASSWORD_EXPIRED) == ADS_UF_PASSWORD_EXPIRED) {
                return false;
            }
        }
        Boolean passwordExpired = getBooleanAttribute(user, ATTR_USER_PASSWORD_EXPIRED);
        if (passwordExpired != null) {
            return !passwordExpired;
        }
        // no other indicators
        return true;
    }

    // https://ldapwiki.com/wiki/Account%20Lockout
    // https://ldapwiki.com/wiki/Intruder%20Detection
    public static boolean checkIfAccountNonLocked(@Nonnull Attributes user) {
        // Active Directory attributes
        Integer uac = getUserAccountControl(user);
        if (uac != null && (uac & ADS_UF_LOCK_OUT) == ADS_UF_LOCK_OUT) {
            return false;
        }
        // standard attributes
        Boolean lockout = getBooleanAttribute(user, ATTR_PWD_LOCKOUT);
        if (lockout != null) {
            return !lockout;
        }
        // EDirectory attributes
        Moment resetTime = getGeneralizedTimeAttribute(user, ATTR_LOGIN_INTRUDER_RESET_TIME);
        if (resetTime != null) {
            return resetTime.isAfter(Moment.nowInSystemTime());
        }
        // no other indicators
        return true;
    }

    private static @CheckForNull Integer getUserAccountControl(@Nonnull Attributes user) {
        String uac = getStringAttribute(user, ATTR_USER_ACCOUNT_CONTROL);
        String computedUac = getStringAttribute(user, ATTR_USER_ACCOUNT_CONTROL_COMPUTED);
        if (uac == null) {
            return computedUac == null ? null : Integer.parseInt(computedUac);
        } else if (computedUac == null) {
            return Integer.parseInt(uac);
        } else {
            return Integer.parseInt(uac) | Integer.parseInt(computedUac);
        }
    }

    private static @CheckForNull Boolean getBooleanAttribute(@Nonnull Attributes user, @Nonnull String attrID) {
        String attr = getStringAttribute(user, attrID);
        return attr == null ? null : "true".equalsIgnoreCase(attr);
    }

    private static @CheckForNull Moment getGeneralizedTimeAttribute(@Nonnull Attributes user, @Nonnull String attrID) {
        String attr = getStringAttribute(user, attrID);
        try {
            return attr == null ? null : GENERALIZED_TIME_FORMATTER.parse(attr);
        } catch (ParseException e) {
            LOGGER.log(Level.WARNING, e, () -> "Cannot parse generalized time value of " + attrID);
            return null;
        }
    }

    private static @CheckForNull String getStringAttribute(@Nonnull Attributes user, @Nonnull String name) {
        Attribute a = user.get(name);
        if (a == null || a.size() == 0) {
            return null;
        }
        try {
            Object v = a.get();
            return v == null ? null : v.toString();
        } catch (NamingException e) {
            return null;
        }
    }
}
