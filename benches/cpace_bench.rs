use criterion::{black_box, criterion_group, criterion_main, Criterion};

use cpace::Exchanger;

fn bench_exchanger(c: &mut Criterion) {
    c.bench_function("exchanger", |b| {
        b.iter(|| {
            let alice = Exchanger::new(
                black_box(b"Alice"),
                black_box(b"Bea"),
                black_box(b"our shared secret"),
                black_box(b"session id"),
            );

            let bea = Exchanger::new(
                black_box(b"Bea"),
                black_box(b"Alice"),
                black_box(b"our shared secret"),
                black_box(b"session id"),
            );

            let y_alice = alice.send();
            let y_bea = bea.send();

            let alice = alice.receive(y_bea);
            let bea = bea.receive(y_alice);

            (alice, bea)
        })
    });
}

criterion_group!(benches, bench_exchanger);
criterion_main!(benches);
