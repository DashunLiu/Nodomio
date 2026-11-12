use nodomi_agent::{collect::Collector, source::LinuxSource};
use std::{
    ffi::OsStr,
    io::{self, Write},
    time::Duration,
};

#[cfg(target_os = "linux")]
mod service;

fn arguments() -> Result<(u32, u64), &'static str> {
    let mut args = std::env::args().skip(1);
    let (mut samples, mut interval) = (2, 1000);
    let (mut saw_samples, mut saw_interval) = (false, false);
    while let Some(arg) = args.next() {
        let value = args.next().ok_or("expected a value")?;
        if !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err("expected an unsigned decimal integer");
        }
        match arg.as_str() {
            "--samples" if !saw_samples => {
                samples = value.parse().map_err(|_| "invalid sample count")?;
                saw_samples = true;
            }
            "--interval-ms" if !saw_interval => {
                interval = value.parse().map_err(|_| "invalid interval")?;
                saw_interval = true;
            }
            _ => return Err("unknown or repeated option"),
        }
    }
    if !(1..=10).contains(&samples) || !(10..=60_000).contains(&interval) {
        return Err("samples must be 1..10; interval-ms must be 10..60000");
    }
    Ok((samples, interval))
}
fn run() -> Result<(), String> {
    let (samples, interval) = arguments().map_err(|error| {
        format!("{error}; usage: nodomi-agent [--samples 1..10] [--interval-ms 10..60000]")
    })?;
    let mut collector = Collector::new("diagnostic");
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for index in 0..samples {
        if index > 0 {
            std::thread::sleep(Duration::from_millis(interval));
        }
        let raw = LinuxSource
            .capture()
            .map_err(|error| format!("Linux source unavailable: {error:?}"))?;
        let snapshot = collector.collect(raw);
        serde_json::to_writer(&mut output, &snapshot)
            .map_err(|_| "cannot write diagnostic output")?;
        writeln!(output).map_err(|_| "cannot write diagnostic output")?;
        output
            .flush()
            .map_err(|_| "cannot write diagnostic output")?;
    }
    Ok(())
}
fn main() {
    let mut args = std::env::args_os().skip(1);
    let result = if args.next().as_deref() == Some(OsStr::new("serve")) {
        let remaining = args.collect::<Vec<_>>();
        match run_service(&remaining) {
            Ok(0) => return,
            Ok(code) => std::process::exit(i32::from(code)),
            Err(error) => Err(error.to_owned()),
        }
    } else {
        run()
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run_service(args: &[std::ffi::OsString]) -> Result<u8, &'static str> {
    let [flag, fd] = args else {
        return Err("INVALID_SERVICE_ARGUMENTS");
    };
    let fd = fd
        .to_str()
        .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<i32>().ok())
        .filter(|fd| *fd >= 3)
        .ok_or("INVALID_SERVICE_ARGUMENTS")?;
    if flag != "--supervisor-lock-fd" {
        return Err("INVALID_SERVICE_ARGUMENTS");
    }
    #[cfg(target_os = "linux")]
    {
        service::run(fd).map(|result| match result {
            service::Exit::Stopped => 0,
            service::Exit::AwaitingTakeover => {
                nodomi_agent::installation::AWAITING_INSTALL_TAKEOVER_EXIT
            }
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        Err("UNSUPPORTED_HOST")
    }
}
