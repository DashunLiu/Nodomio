CREATE TABLE source_checkpoints (
    stream TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    cursor BLOB NOT NULL CHECK (length(cursor) BETWEEN 1 AND 4096),
    last_event_id TEXT UNIQUE,
    -- A SHA-256 for an event, or one byte for a final source disposition.
    last_outcome BLOB NOT NULL CHECK (
        (length(last_outcome) = 32 AND last_event_id IS NOT NULL)
        OR last_outcome IN (X'01', X'02', X'03')),
    last_read_at INTEGER CHECK (last_read_at BETWEEN 1 AND 253402300799),
    source_witness BLOB CHECK (length(source_witness) BETWEEN 1 AND 4096),
    gap_reason INTEGER CHECK (gap_reason IN (1,2,3,4)),
    gap_detected_at INTEGER CHECK (
        (gap_reason IS NULL AND gap_detected_at IS NULL)
        OR (gap_reason IS NOT NULL AND gap_detected_at IS NOT NULL
            AND gap_detected_at BETWEEN 1 AND 253402300799)),
    gap_recovered_at INTEGER CHECK (
        gap_recovered_at IS NULL
        OR (gap_detected_at IS NOT NULL AND gap_recovered_at BETWEEN 1 AND 253402300799))
) STRICT;
