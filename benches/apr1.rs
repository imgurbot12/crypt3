use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};

use crypt3_rs::crypt::apr1;

fn hash() {
    #[allow(deprecated)]
    apr1::hash("password").unwrap();
}

fn verify(password: &str, hash: &str) {
    assert!(apr1::verify(password, hash));
}

fn criterion_benchmark(c: &mut Criterion) {
    #[allow(deprecated)]
    let base = apr1::hash("password").unwrap();

    c.bench_function("hash", |b| b.iter(|| black_box(hash())));
    c.bench_function("verify", |b| {
        b.iter(|| black_box(verify(black_box("password"), black_box(&base))))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
