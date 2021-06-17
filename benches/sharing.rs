use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, Bencher, BenchmarkGroup,
    BenchmarkId, Criterion, Throughput,
};
use merlin::Transcript;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use elgamal_with_sharing::{
    group::{Curve25519Subgroup, Generic, Group, Ristretto},
    Keypair, ProofOfPossession,
};

type K256 = Generic<k256::Secp256k1>;

fn bench_proof_of_possession<G: Group>(b: &mut Bencher, degree: usize) {
    let mut rng = ChaChaRng::from_seed([10; 32]);
    let keypairs: Vec<_> = (0..degree)
        .map(|_| Keypair::<G>::generate(&mut rng))
        .collect();

    b.iter(|| ProofOfPossession::new(&keypairs, &mut Transcript::new(b"bench_pop"), &mut rng));
}

fn bench_proof_of_possession_verification<G: Group>(b: &mut Bencher, degree: usize) {
    let mut rng = ChaChaRng::from_seed([10; 32]);
    let keypairs: Vec<_> = (0..degree)
        .map(|_| Keypair::<G>::generate(&mut rng))
        .collect();

    b.iter_batched(
        || ProofOfPossession::new(&keypairs, &mut Transcript::new(b"bench_pop"), &mut rng),
        |proof| {
            proof.verify(
                keypairs.iter().map(Keypair::public),
                &mut Transcript::new(b"bench_pop"),
            )
        },
        BatchSize::SmallInput,
    );
}

fn bench_group<G: Group>(group: &mut BenchmarkGroup<'_, WallTime>) {
    const PARTICIPANTS: &[usize] = &[2, 3, 5, 10, 15, 20];

    group.throughput(Throughput::Elements(1));

    // Proof of polynomial possession.
    for &participants in PARTICIPANTS {
        group.bench_with_input(
            BenchmarkId::new("pop_prove", participants),
            &participants,
            |b, &degree| bench_proof_of_possession::<G>(b, degree),
        );
    }
    for &participants in PARTICIPANTS {
        group.bench_with_input(
            BenchmarkId::new("pop_verify", participants),
            &participants,
            |b, &degree| bench_proof_of_possession_verification::<G>(b, degree),
        );
    }

    // Helpers: bench different methods to compute polynomials of form
    //
    //     Q(i) = C_0 + [i]C_1 + [i^2]C_2 + ...
    //
    // where `i` is a small positive integer. We use `i = 5` and polynomial of 9th degree.
    //
    // Spoilers: `pure_varmul` is by far the best method.
    let mut rng = ChaChaRng::from_seed([100; 32]);
    let coefficients: Vec<_> = (0..10)
        .map(|_| G::mul_generator(&G::generate_scalar(&mut rng)))
        .collect();
    let coefficients1 = coefficients.clone();
    let coefficients2 = coefficients.clone();

    group.bench_function("poly/naive", move |b| {
        let variable = G::Scalar::from(5_u64);
        b.iter(|| {
            let mut x = G::Scalar::from(1_u64);
            let mut value = G::identity();
            for &coefficient in &coefficients {
                value = value + coefficient * &x;
                x = x * variable;
            }
            value
        });
    });
    group.bench_function("poly/weierstrass_varmul", move |b| {
        let variable = G::Scalar::from(5_u64);
        b.iter(|| {
            let mut value = G::identity();
            for &coefficient in coefficients1.iter().rev() {
                value = G::vartime_multi_mul(
                    &[variable, G::Scalar::from(1_u64)],
                    [value, coefficient].iter().copied(),
                );
            }
            value
        });
    });
    group.bench_function("poly/pure_varmul", move |b| {
        let variable = G::Scalar::from(5_u64);
        let mut val = G::Scalar::from(1_u64);
        let scalars: Vec<_> = (0..coefficients2.len())
            .map(|_| {
                let output = val;
                val = val * variable;
                output
            })
            .collect();
        b.iter(|| G::vartime_multi_mul(&scalars, coefficients2.iter().copied()));
    });
}

fn bench_curve25519(criterion: &mut Criterion) {
    bench_group::<Curve25519Subgroup>(&mut criterion.benchmark_group("curve25519"));
}

fn bench_ristretto(criterion: &mut Criterion) {
    bench_group::<Ristretto>(&mut criterion.benchmark_group("ristretto"));
}

fn bench_k256(criterion: &mut Criterion) {
    bench_group::<K256>(&mut criterion.benchmark_group("k256"));
}

criterion_group!(benches, bench_curve25519, bench_ristretto, bench_k256);
criterion_main!(benches);
