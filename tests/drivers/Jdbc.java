import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * pgjdbc against the session allowlist. Run by tests/drivers.sh, which sets up the
 * database and passes DB, ROLE, MINE, THEIRS, GATE_HOST and PGPORT.
 *
 * Every attack reads through the gate on the SAME connection that tried to move the
 * tenant, because that is the only place it can come out wrong. A refusal counts only
 * when it is the gate's own (its message starts with "pg_agent_gate:"): an unrelated
 * error that happens to show no rows is not a pass.
 */
public class Jdbc {
    static final String URL = "jdbc:postgresql://" + env("GATE_HOST", "localhost") + ":" + env("PGPORT", "5499") + "/" + env("DB", null);
    static final String ROLE = env("ROLE", null);
    static final String MINE = env("MINE", null);
    static final String THEIRS = env("THEIRS", null);
    static final String READ_SQL = "select body from docs order by 1";
    static final String GATE = "pg_agent_gate:";
    static final Pattern PROPOSAL = Pattern.compile("\"proposal\":\\s*(\\d+)");

    interface Body {
        String run() throws Exception;
    }

    static String env(String key, String fallback) {
        String v = System.getenv(key);
        if (v != null && !v.isEmpty()) return v;
        if (fallback == null) throw new IllegalStateException("missing environment variable " + key);
        return fallback;
    }

    static Connection connect(Properties extra) throws SQLException {
        Properties p = new Properties();
        p.setProperty("user", ROLE);
        if (extra != null) p.putAll(extra);
        return DriverManager.getConnection(URL, p);
    }

    static Properties props(String key, String value) {
        Properties p = new Properties();
        p.setProperty(key, value);
        return p;
    }

    static String one(Connection c, String sql, Object... args) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) ps.setObject(i + 1, args[i]);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    static String attempt(Connection c, String sql) {
        try (Statement s = c.createStatement()) {
            s.execute(sql);
            return "accepted";
        } catch (SQLException e) {
            return "error: " + e.getMessage();
        }
    }

    /** Propose the read and commit it on THIS connection, with bound parameters. */
    static String read(Connection c) {
        try {
            String proposed = one(c, "select agent_gate.propose(?, ?)", READ_SQL, "read the documents I may read");
            Matcher m = PROPOSAL.matcher(String.valueOf(proposed));
            if (!m.find()) return "no proposal id in: " + proposed;
            return one(c, "select agent_gate.commit(?)", Integer.parseInt(m.group(1)));
        } catch (SQLException e) {
            return "error: " + e.getMessage();
        }
    }

    static String safely(Body body) {
        try {
            return body.run();
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }

    static boolean ownOnly(String got) {
        return got != null && got.contains(MINE) && !got.contains(THEIRS);
    }

    static boolean refusedByGate(String got) {
        return got.startsWith("error") && got.contains(GATE);
    }

    static void check(String kind, String what, boolean ok, String got) {
        System.out.println("  " + (ok ? "ok  " : "FAIL") + " [" + kind + "] " + what);
        if (!ok) System.out.println("       got: " + String.valueOf(got).replace('\n', ' '));
    }

    public static void main(String[] args) {
        String got;

        // ------------------------------------------------------------ attacks --
        got = safely(() -> {
            try (Connection c = connect(props("options", "-c app.tenant_id=2"))) {
                return read(c);
            }
        });
        check("attack", "pgjdbc: options=-c app.tenant_id at connect does not move the tenant",
                !got.contains(THEIRS) && (got.contains(MINE) || refusedByGate(got)), got);

        got = safely(() -> {
            try (Connection c = connect(null)) {
                return attempt(c, "set app.tenant_id = '2'") + " | " + read(c);
            }
        });
        check("attack", "pgjdbc: SET through a Statement does not move the tenant", ownOnly(got), got);

        got = safely(() -> {
            try (Connection c = connect(null)) {
                c.setAutoCommit(false);
                String tried = attempt(c, "set local app.tenant_id = '2'");
                if (tried.startsWith("error")) c.rollback();
                String read = read(c);
                c.commit();
                boolean ok = !read.contains(THEIRS) && (read.contains(MINE) || refusedByGate(tried));
                return (ok ? "PASS " : "") + tried + " | " + read;
            }
        });
        check("attack", "pgjdbc: SET LOCAL inside a transaction does not move the tenant", got.startsWith("PASS "), got);

        // -------------------------------------------------------------- legit --
        got = safely(() -> {
            try (Connection c = connect(null)) {
                return one(c, "select agent_gate.whoami()");
            }
        });
        check("legit", "pgjdbc: connects as the agent and whoami answers", got.contains("\"is_agent\": true"), got);

        got = safely(() -> {
            try (Connection c = connect(null)) {
                return read(c);
            }
        });
        check("legit", "pgjdbc: propose and commit with bound parameters read its own tenant", ownOnly(got), got);

        got = safely(() -> {
            try (Connection c = connect(null)) {
                c.setAutoCommit(false);
                String w = one(c, "select agent_gate.whoami()");
                c.commit();
                return w;
            }
        });
        check("legit", "pgjdbc: setAutoCommit(false) and commit around a verb", got.contains("\"is_agent\": true"), got);

        got = safely(() -> {
            try (Connection c = connect(null)) {
                c.setAutoCommit(false);
                c.setReadOnly(true);
                String w = one(c, "select agent_gate.whoami()");
                c.commit();
                return w;
            }
        });
        check("legit", "pgjdbc: setReadOnly(true) in a transaction", got.contains("\"is_agent\": true"), got);

        got = safely(() -> {
            try (Connection c = connect(null)) {
                c.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
                return one(c, "show transaction_isolation") + " | " + one(c, "select agent_gate.whoami()");
            }
        });
        check("legit", "pgjdbc: setTransactionIsolation(SERIALIZABLE)",
                got.startsWith("serializable") && got.contains("\"is_agent\": true"), got);

        got = safely(() -> {
            try (Connection c = connect(props("options", "-c statement_timeout=5000"))) {
                return one(c, "show statement_timeout");
            }
        });
        check("legit", "pgjdbc: a statement_timeout passed through options still applies", "5s".equals(got), got);

        got = safely(() -> {
            try (Connection c = connect(props("ApplicationName", "gate-drivers-jdbc"))) {
                return one(c, "show application_name");
            }
        });
        check("legit", "pgjdbc: ApplicationName is set", "gate-drivers-jdbc".equals(got), got);
    }
}
