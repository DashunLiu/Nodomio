CREATE TABLE queue_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    owner TEXT NOT NULL,
    payload_bytes INTEGER NOT NULL DEFAULT 0 CHECK (payload_bytes >= 0),
    last_boot TEXT,
    last_monotonic_ns INTEGER NOT NULL DEFAULT 0 CHECK (last_monotonic_ns >= 0),
    last_wall_seconds INTEGER NOT NULL DEFAULT 0 CHECK (last_wall_seconds >= 0),
    wall_uncertain INTEGER NOT NULL DEFAULT 0 CHECK (wall_uncertain IN (0,1)),
    elapsed_ns INTEGER NOT NULL DEFAULT 0 CHECK (elapsed_ns >= 0),
    flight_first INTEGER,
    flight_last INTEGER,
    flight_count INTEGER,
    isolation_last INTEGER CHECK (isolation_last > 0),
    batch_limit INTEGER NOT NULL DEFAULT 1000 CHECK (batch_limit BETWEEN 1 AND 1000),
    quarantined_count INTEGER NOT NULL DEFAULT 0 CHECK (quarantined_count >= 0),
    capacity_discarded_count INTEGER NOT NULL DEFAULT 0 CHECK (capacity_discarded_count >= 0),
    source_counter_epoch TEXT CHECK (length(source_counter_epoch) = 36),
    unknown_format_records_total BLOB CHECK (length(unknown_format_records_total) = 8),
    oversized_records_total BLOB CHECK (length(oversized_records_total) = 8),
    CHECK ((flight_first IS NULL AND flight_last IS NULL AND flight_count IS NULL)
        OR (flight_first > 0 AND flight_last >= flight_first AND flight_count BETWEEN 1 AND 1000))
) STRICT;

CREATE TABLE ssh_events (
    id INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    admitted_ns INTEGER NOT NULL CHECK (admitted_ns >= 0),
    body BLOB NOT NULL CHECK (length(body) BETWEEN 1 AND 1048563),
    quarantine_code TEXT CHECK (quarantine_code IN ('TOO_LARGE', 'INVALID', 'CONFLICT'))
) STRICT;
CREATE INDEX ssh_events_expiry ON ssh_events (admitted_ns, id);
CREATE INDEX ssh_events_ready ON ssh_events (id) WHERE quarantine_code IS NULL;
