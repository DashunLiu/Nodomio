//! Internal read-only storage diagnostic. Not agentctl, an installer or a TUF doctor.
use nodomi_agent::trust_storage::{ExpectedInstallation, StorageError, inspect_existing};
use std::path::Path;
fn run() -> Result<(), StorageError> {
    let mut args = std::env::args().skip(1);
    let (mut path, mut installation, mut source, mut owner) = (None, None, None, None);
    while let Some(option) = args.next() {
        let value = args.next().ok_or(StorageError::InvalidContext)?;
        let slot = match option.as_str() {
            "--state-dir" => &mut path,
            "--installation-id" => &mut installation,
            "--source-config-id" => &mut source,
            "--owner-uid" => &mut owner,
            _ => return Err(StorageError::InvalidContext),
        };
        if slot.replace(value).is_some() {
            return Err(StorageError::InvalidContext);
        }
    }
    let owner = owner.ok_or(StorageError::InvalidContext)?;
    if owner.is_empty() || !owner.bytes().all(|b| b.is_ascii_digit()) {
        return Err(StorageError::InvalidContext);
    }
    // All expectations are independent explicit inputs; no field is inferred from disk.
    // CLI inputs do not authenticate installation provenance and never grant trust.
    let expected = ExpectedInstallation::new(
        Path::new(&path.ok_or(StorageError::InvalidContext)?),
        &installation.ok_or(StorageError::InvalidContext)?,
        &source.ok_or(StorageError::InvalidContext)?,
        owner.parse().map_err(|_| StorageError::InvalidContext)?,
    )?;
    let snapshot = inspect_existing(&expected)?;
    println!(
        "{}",
        serde_json::json!({"diagnosticOnly":true,"storageEnvelope":"STRUCTURALLY_VALID_UNVERIFIED","verifier":"NOT_CONNECTED","generation":snapshot.generation()})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", error.code());
        std::process::exit(2);
    }
}
