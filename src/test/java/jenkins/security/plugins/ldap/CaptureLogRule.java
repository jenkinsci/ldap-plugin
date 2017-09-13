package jenkins.security.plugins.ldap;


import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

public class CaptureLogRule extends Handler implements TestRule {

    private final String logId;
    private final List<LogRecord> records;

    public CaptureLogRule(@Nonnull String logId, @CheckForNull Level level) {
        this.logId = logId;
        setLevel(level != null ? level : Level.ALL);
        records = new ArrayList<>();
    }

    @Override
    public void publish(LogRecord record) {
        if (isLoggable(record)) {
            synchronized (records) {
                records.add(record);
            }
        }
    }

    @Override
    public void flush() {

    }

    @Override
    public void close() throws SecurityException {

    }

    public void assertRecorded(@CheckForNull Level level, @Nonnull Matcher<String> message, @CheckForNull Matcher<Throwable> thrown) {
        assertThat(this, recorded(level, message, thrown));
    }

    public void assertNotRecorded(@CheckForNull Level level, @Nonnull Matcher<String> message, @CheckForNull Matcher<Throwable> thrown) {
        assertThat(this, not(recorded(level, message, thrown)));
    }

    public Matcher<CaptureLogRule> recorded(@CheckForNull Level level, @Nonnull Matcher<String> message, @CheckForNull Matcher<Throwable> thrown) {
        return new RecordedMatcher(level, message, thrown);
    }

    public void assertRecorded(@CheckForNull Level level, @Nonnull Matcher<String> message) {
        assertThat(this, recorded(level, message));
    }

    public Matcher<CaptureLogRule> recorded(@CheckForNull Level level, @Nonnull Matcher<String> message) {
        return recorded(level, message, null);
    }

    public void assertRecorded(@Nonnull Matcher<String> message, @CheckForNull Matcher<Throwable> thrown) {
        assertThat(this, recorded(message, thrown));
    }

    public Matcher<CaptureLogRule> recorded(@Nonnull Matcher<String> message, @CheckForNull Matcher<Throwable> thrown) {
        return recorded(null, message, thrown);
    }

    public void assertRecorded(@Nonnull Matcher<String> message) {
        assertThat(this, recorded(message));
    }

    public Matcher<CaptureLogRule> recorded(@Nonnull Matcher<String> message) {
        return recorded(null, message);
    }

    @Override
    public Statement apply(final Statement base, Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                synchronized (records) {
                    records.clear();
                }
                final Logger logger = Logger.getLogger(logId);
                logger.addHandler(CaptureLogRule.this);
                try {
                    base.evaluate();
                } finally {
                    logger.removeHandler(CaptureLogRule.this);
                    synchronized (records) {
                        records.clear();
                    }
                }
            }
        };
    }

    public static class RecordedMatcher extends TypeSafeMatcher<CaptureLogRule> {
        @CheckForNull Level level;
        @Nonnull Matcher<String> message;
        @CheckForNull Matcher<Throwable> thrown;

        public RecordedMatcher(Level level, @Nonnull Matcher<String> message, Matcher<Throwable> thrown) {
            this.level = level;
            this.message = message;
            this.thrown = thrown;
        }

        @Override
        protected boolean matchesSafely(CaptureLogRule item) {
            synchronized (item.records) {
                for (LogRecord record : item.records) {
                    if (this.level != null && record.getLevel() == this.level) {
                        if (message.matches(record.getMessage())) {
                            if (thrown != null) {
                                if (thrown.matches(record.getThrown())) {
                                    return true;
                                }
                            } else {
                                return true;
                            }
                        }
                    } else if (this.level == null) {
                        if (message.matches(record.getMessage())) {
                            if (thrown != null) {
                                if (thrown.matches(record.getThrown())) {
                                    return true;
                                }
                            } else {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

        @Override
        public void describeTo(org.hamcrest.Description description) {
            description.appendText("has LogRecord");
            if (level != null) {
                description.appendText(" with level ");
                description.appendValue(level.getName());
            }
            description.appendText(" with a message that ");
            description.appendDescriptionOf(message);
            if (thrown != null) {
                description.appendText(" with an exception matching ");
                description.appendDescriptionOf(thrown);
            }

        }
    }
}
