use nodomi_agent::protocol::{AgentConfiguration, AgentIdentity, HeartbeatAck};
#[test]
fn identity_rejects_wrong_cadence_invalid_ids_dates_unknown_and_duplicate_fields() {
    let valid = r#"{"agentId":"agent:one","serverId":"server-1","samplingIntervalSeconds":30,"heartbeatIntervalSeconds":30,"registeredAt":"2026-11-10T00:00:00Z","bindingRevision":2}"#;
    assert!(AgentIdentity::decode(valid.as_bytes()).is_ok());
    for invalid in [
        valid.replace(
            "\"heartbeatIntervalSeconds\":30",
            "\"heartbeatIntervalSeconds\":1",
        ),
        valid.replace("agent:one", "agent/one"),
        valid.replace("2026-11-10T00:00:00Z", "tomorrow"),
        valid.replace(
            "\"bindingRevision\":2",
            "\"bindingRevision\":2,\"surprise\":true",
        ),
        valid.replace(
            "\"bindingRevision\":2",
            "\"bindingRevision\":2,\"bindingRevision\":3",
        ),
    ] {
        assert!(AgentIdentity::decode(invalid.as_bytes()).is_err());
    }
}
#[test]
fn config_and_ack_validate_exact_protocol_boundaries() {
    let config = r#"{"agentId":"agent:one","bindingRevision":2,"schemaVersion":1,"target":{"configId":"123e4567-e89b-42d3-a456-426614174000","generation":1,"configuration":{"samplingIntervalSeconds":30,"bufferMaxAgeSeconds":86400,"bufferMaxBytes":100000000}}}"#;
    assert!(AgentConfiguration::decode(config.as_bytes()).is_ok());
    assert!(
        AgentConfiguration::decode(
            config
                .replace("\"schemaVersion\":1", "\"schemaVersion\":2")
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        AgentConfiguration::decode(config.replace("100000000}", "999999}").as_bytes()).is_err()
    );
    assert!(HeartbeatAck::decode(br#"{"receivedAt":"2026-11-10T00:00:00Z","samplingIntervalSeconds":4,"heartbeatIntervalSeconds":30}"#).is_err());
}
