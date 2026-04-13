//! `cachee bench` — built-in throughput/latency benchmark.

use cachee_core::{CacheeEngine, EngineConfig, L0Config};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub async fn run(duration_secs: u64, workers: usize) -> anyhow::Result<()> {
    println!("Cachee Benchmark");
    println!("  Duration : {}s", duration_secs);
    println!("  Workers  : {}", workers);
    println!();

    let engine = Arc::new(CacheeEngine::new(EngineConfig {
        max_keys: 1_000_000,
        default_ttl: 3600,
        l0: L0Config { enabled: true, max_keys: 100_000, shards: 64 },
        ..Default::default()
    }));

    // Pre-populate 10K keys
    let populate_count = 10_000;
    println!("  Populating {} keys...", populate_count);
    for i in 0..populate_count {
        let key = format!("bench:key:{i}");
        let value = format!("value-{i}-{}", "x".repeat(64));
        engine.set(key, bytes::Bytes::from(value), None);
    }

    let total_ops = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    println!("  Running mixed workload (80% GET / 20% SET)...");
    println!();
    println!("  {:>4}  {:>12}  {:>12}", "Sec", "Ops/s", "Total");
    println!("  {}", "-".repeat(35));

    let start = Instant::now();

    // Reporter
    let report_total = total_ops.clone();
    let report_stop = stop.clone();
    let reporter = std::thread::spawn(move || {
        let mut prev = 0u64;
        for sec in 1..=duration_secs {
            std::thread::sleep(Duration::from_secs(1));
            if report_stop.load(Ordering::Relaxed) { break; }
            let current = report_total.load(Ordering::Relaxed);
            println!("  {:>4}  {:>12}  {:>12}", sec, current - prev, current);
            prev = current;
        }
    });

    // Workers
    std::thread::scope(|s| {
        for tid in 0..workers {
            let engine = engine.clone();
            let total_ops = total_ops.clone();
            let stop = stop.clone();

            s.spawn(move || {
                let mut i = tid as u64 * 1_000_000;
                while !stop.load(Ordering::Relaxed) {
                    let key_idx = (i % populate_count as u64) as usize;
                    let key = format!("bench:key:{key_idx}");

                    if i % 5 == 0 {
                        // 20% writes
                        let value = format!("updated-{i}");
                        engine.set(key, bytes::Bytes::from(value), None);
                    } else {
                        // 80% reads
                        let _ = engine.get(&key);
                    }

                    total_ops.fetch_add(1, Ordering::Relaxed);
                    i += 1;
                }
            });
        }

        std::thread::sleep(Duration::from_secs(duration_secs));
        stop.store(true, Ordering::Relaxed);
    });

    let elapsed = start.elapsed();
    let final_ops = total_ops.load(Ordering::Relaxed);
    let _ = reporter.join();

    let ops_per_sec = final_ops as f64 / elapsed.as_secs_f64();
    let us_per_op = elapsed.as_secs_f64() * 1_000_000.0 / final_ops as f64;

    let stats = engine.stats();

    println!();
    println!("  --- Results ---");
    println!("  Total ops     : {final_ops}");
    println!("  Throughput    : {:.0} ops/sec", ops_per_sec);
    println!("  Latency       : {:.3} us/op", us_per_op);
    println!("  Hit rate      : {:.2}%", stats.hit_rate * 100.0);
    println!("  L0 hits       : {}", stats.hits.l0);
    println!("  L1 hits       : {}", stats.hits.l1);
    println!("  Misses        : {}", stats.misses);
    println!("  Memory        : {} bytes", stats.memory_bytes);
    println!("  Keys          : {}", stats.key_count);

    Ok(())
}
