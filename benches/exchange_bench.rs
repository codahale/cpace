use criterion::{black_box, criterion_group, criterion_main, Criterion};

use cpace::{Initiator, Responder};

fn bench_exchange(c: &mut Criterion) {
    c.bench_function("exchange", |b| {
        b.iter(|| {
            let mut initiator = Initiator::new(
                black_box(b"Alice"),
                black_box(b"Bea"),
                black_box(b"our shared secret"),
            );
            let (salt_a, a) = initiator.start();

            let mut responder = Responder::new(
                black_box(b"Bea"),
                black_box(b"Alice"),
                black_box(b"our shared secret"),
            );
            let (salt_b, b) = responder.start(salt_a, a);

            let one = initiator.finish(salt_b, b);
            let two = responder.finish();

            (one, two)
        })
    });
}

criterion_group!(benches, bench_exchange);
criterion_main!(benches);
