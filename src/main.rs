use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use dynamic_dns_updater::cloudflare::CloudflareClient;
use dynamic_dns_updater::config::AppConfig;
use dynamic_dns_updater::error::{Result, UpdaterError};
use dynamic_dns_updater::logging;
use dynamic_dns_updater::reconciler::{CycleReport, Reconciler};
use dynamic_dns_updater::tplink::TpLinkClient;

/// Loads configuration, selects one-shot or daemon mode, and maps outcomes to process exit status.
fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            logging::error(error.to_string());
            ExitCode::FAILURE
        }
    }
}

/// Constructs production providers and drives the requested process lifecycle.
fn run() -> Result<bool> {
    let once = parse_once_argument()?;
    let config = AppConfig::from_environment()?;
    logging::info(format!(
        "dynamic_dns_updater_start version={} mode={} interval_seconds={} records={} router_host={} cloudflare_origin={}",
        env!("CARGO_PKG_VERSION"),
        if once { "once" } else { "daemon" },
        config.interval.as_secs(),
        config.records.len(),
        config.router_host,
        config.cloudflare_base_url
    ));
    let AppConfig {
        router_host,
        router_password,
        cloudflare_base_url,
        cloudflare_auth,
        interval,
        http_timeout,
        records,
    } = config;
    let router = TpLinkClient::new(router_host, router_password, http_timeout)?;
    let cloudflare = CloudflareClient::new(cloudflare_base_url, cloudflare_auth, http_timeout)?;
    let reconciler = Reconciler::new(&router, &cloudflare, &records);
    if once {
        return Ok(run_and_report(&reconciler));
    }
    run_daemon(&reconciler, interval)
}

/// Accepts only the supported `--once` switch so deployment mistakes fail closed.
fn parse_once_argument() -> Result<bool> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [] => Ok(false),
        [argument] if argument == "--once" => Ok(true),
        _ => Err(UpdaterError::Config(
            "usage: dynamic-dns-updater [--once]".into(),
        )),
    }
}

/// Runs immediate and scheduled cycles until Ctrl-C requests a prompt graceful exit.
fn run_daemon<W, D>(reconciler: &Reconciler<'_, W, D>, interval: Duration) -> Result<bool>
where
    W: dynamic_dns_updater::tplink::WanIpProvider,
    D: dynamic_dns_updater::cloudflare::DnsProvider,
{
    let running = Arc::new(AtomicBool::new(true));
    let signal = Arc::clone(&running);
    ctrlc::set_handler(move || signal.store(false, Ordering::SeqCst)).map_err(|error| {
        UpdaterError::Config(format!("failed to install shutdown handler: {error}"))
    })?;
    while running.load(Ordering::SeqCst) {
        run_and_report(reconciler);
        wait_for_interval(interval, &running);
    }
    logging::info("dynamic_dns_updater_stop reason=shutdown_signal");
    Ok(true)
}

/// Executes one cycle and converts both provider errors and partial reports to a success flag.
fn run_and_report<W, D>(reconciler: &Reconciler<'_, W, D>) -> bool
where
    W: dynamic_dns_updater::tplink::WanIpProvider,
    D: dynamic_dns_updater::cloudflare::DnsProvider,
{
    match reconciler.run_cycle() {
        Ok(report) => report_succeeded(report),
        Err(error) => {
            logging::error(format!("cycle_complete success=false error={error}"));
            false
        }
    }
}

/// Logs partial reconciliation failure without discarding the report's successful work.
fn report_succeeded(report: CycleReport) -> bool {
    if !report.succeeded() {
        logging::error(format!("cycle_failed failed_records={}", report.failed));
    }
    report.succeeded()
}

/// Waits in short increments so the daemon responds promptly to Ctrl-C during the interval.
fn wait_for_interval(interval: Duration, running: &AtomicBool) {
    let deadline = Instant::now() + interval;
    while running.load(Ordering::SeqCst) && Instant::now() < deadline {
        thread::sleep(
            Duration::from_millis(250).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies a cleared shutdown flag prevents the scheduler from sleeping for the configured interval.
    #[test]
    fn shutdown_flag_skips_interval_wait() {
        let running = AtomicBool::new(false);
        let started = Instant::now();
        wait_for_interval(Duration::from_secs(5), &running);
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
