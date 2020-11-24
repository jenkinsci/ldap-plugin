/*
 * Copyright (c) 2017 Meno Hochschild, and 2020 CloudBees, Inc.
 *
 * This work is licensed under the Creative Commons Attribution-ShareAlike 3.0 Unported License.
 * To view a copy of this license, visit http://creativecommons.org/licenses/by-sa/3.0/ or send
 * a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
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

import edu.umd.cs.findbugs.annotations.NonNull;
import net.time4j.Moment;
import net.time4j.PlainDate;
import net.time4j.PlainTime;
import net.time4j.format.DisplayMode;
import net.time4j.format.expert.ChronoFormatter;

import java.text.ParseException;
import java.util.Collections;
import java.util.Locale;

/**
 * GeneralizedTime is an LDAP syntax for specifying a date and time. Due to the complexity in its format (particularly
 * the inclusion of leap seconds which not many datetime libraries support properly), this small wrapper is provided
 * rather than exposing yet another datetime library type.
 *
 * @see <a href="https://ldapwiki.com/wiki/GeneralizedTime">LDAPWiki info about GeneralizedTime</a>
 */
final class GeneralizedTime implements Comparable<GeneralizedTime> {

    public static @NonNull GeneralizedTime parse(@NonNull String timestamp) throws ParseException {
        return new GeneralizedTime(GENERALIZED_TIME_FORMATTER.parse(timestamp));
    }

    public static @NonNull GeneralizedTime now() {
        return new GeneralizedTime(Moment.nowInSystemTime());
    }

    private static final ChronoFormatter<Moment> GENERALIZED_TIME_FORMATTER;

    static {
        // the format for GeneralizedTime in LDAP accounts for LEAP SECONDS (!!!), so here we are, using yet another
        // fancy datetime library that actually _supports_ that concept
        // thanks to https://stackoverflow.com/a/42383153 (CC-BY-SA 3.0)
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

    private final Moment moment;

    private GeneralizedTime(Moment moment) {
        this.moment = moment;
    }

    @Override
    public int compareTo(@NonNull GeneralizedTime that) {
        return this.moment.compareTo(that.moment);
    }

    public boolean isBefore(@NonNull GeneralizedTime that) {
        return this.moment.isBefore(that.moment);
    }

    public boolean isAfter(@NonNull GeneralizedTime that) {
        return this.moment.isAfter(that.moment);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GeneralizedTime that = (GeneralizedTime) o;
        return moment.equals(that.moment);
    }

    @Override
    public int hashCode() {
        return moment.hashCode();
    }

    @Override
    public String toString() {
        return moment.toString();
    }
}
