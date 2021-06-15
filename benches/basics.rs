use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, Bencher, BenchmarkGroup,
    BenchmarkId, Criterion, Throughput,
};
use merlin::Transcript;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use elgamal_with_sharing::{
    group::{Curve25519Subgroup, Group, Ristretto},
    EncryptedChoice, Encryption, Keypair, RingProofBuilder,
};

fn bench_encrypt<G: Group>(b: &mut Bencher) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    let message = G::mul_base_point(&G::generate_scalar(&mut rng));
    b.iter(|| Encryption::new(message, keypair.public(), &mut rng));
}

fn bench_decrypt<G: Group>(b: &mut Bencher) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    let message = G::mul_base_point(&G::generate_scalar(&mut rng));
    b.iter_batched(
        || Encryption::new(message, keypair.public(), &mut rng),
        |encrypted| keypair.secret().decrypt(encrypted),
        BatchSize::SmallInput,
    );
}

fn bench_zero_encryption_proof<G: Group>(b: &mut Bencher) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter(|| Encryption::encrypt_zero(keypair.public(), &mut rng));
}

fn bench_zero_encryption_verification<G: Group>(b: &mut Bencher) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter_batched(
        || Encryption::encrypt_zero(keypair.public(), &mut rng),
        |(encrypted, proof)| assert!(encrypted.verify_zero(keypair.public(), &proof)),
        BatchSize::SmallInput,
    );
}

fn bench_bool_encryption_proof<G: Group>(b: &mut Bencher) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter(|| Encryption::encrypt_bool(rng.gen_bool(0.5), keypair.public(), &mut rng));
}

fn bench_bool_encryption_verification<G: Group>(b: &mut Bencher) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter_batched(
        || Encryption::encrypt_bool(rng.gen_bool(0.5), keypair.public(), &mut rng),
        |(encrypted, proof)| {
            assert!(encrypted.verify_bool(keypair.public(), &proof));
        },
        BatchSize::SmallInput,
    );
}

fn bench_choice_creation<G: Group>(b: &mut Bencher, number_of_variants: usize) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter(|| {
        let choice = rng.gen_range(0..number_of_variants);
        EncryptedChoice::<G>::new(number_of_variants, choice, keypair.public(), &mut rng)
    })
}

fn bench_choice_verification<G: Group>(b: &mut Bencher, number_of_variants: usize) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter_batched(
        || {
            let choice = rng.gen_range(0..number_of_variants);
            EncryptedChoice::<G>::new(number_of_variants, choice, keypair.public(), &mut rng)
        },
        |encrypted| {
            assert!(encrypted.verify(keypair.public()).is_some());
        },
        BatchSize::SmallInput,
    )
}

fn bench_ring<G: Group>(b: &mut Bencher, chosen_values: Option<[usize; 5]>) {
    let mut rng = ChaChaRng::from_seed([120; 32]);
    let (receiver, _) = Keypair::<G>::generate(&mut rng).into_tuple();
    let chosen_values = chosen_values.unwrap_or_else(|| {
        let mut values = [0; 5];
        values.iter_mut().for_each(|v| *v = rng.gen_range(0..4));
        values
    });
    assert!(chosen_values.iter().all(|&i| i < 4));

    let admissible_values = [
        G::identity(),
        G::base_point(),
        G::base_point() + G::base_point(),
        G::base_point() + G::base_point() + G::base_point(),
    ];
    b.iter(|| {
        let mut transcript = Transcript::new(b"bench_ring");
        let mut builder = RingProofBuilder::new(&receiver, &mut transcript, &mut rng);
        for &value_index in &chosen_values {
            builder.add_value(&admissible_values, value_index);
        }
        builder.build()
    });
}

fn bench_group<G: Group>(group: &mut BenchmarkGroup<'_, WallTime>) {
    group
        // Basic operations: encryption / decryption.
        .bench_function("encrypt", bench_encrypt::<G>)
        .bench_function("decrypt", bench_decrypt::<G>)
        // Operations related to re-encryption ZKP.
        .bench_function("zero_prove", bench_zero_encryption_proof::<G>)
        .bench_function("zero_verify", bench_zero_encryption_verification::<G>)
        // Operations related to bool flag encryption / ZKP.
        .bench_function("bool_prove", bench_bool_encryption_proof::<G>)
        .bench_function("bool_verify", bench_bool_encryption_verification::<G>)
        .throughput(Throughput::Elements(1));

    // Choice encryption.
    const CHOICE_SIZES: &[usize] = &[2, 3, 5, 10, 15];

    for &choice_size in CHOICE_SIZES {
        group.bench_with_input(
            BenchmarkId::new("choice_prove", choice_size),
            &choice_size,
            |b, &size| bench_choice_creation::<G>(b, size),
        );
    }
    for &choice_size in CHOICE_SIZES {
        group.bench_with_input(
            BenchmarkId::new("choice_verify", choice_size),
            &choice_size,
            |b, &size| bench_choice_verification::<G>(b, size),
        );
    }

    // A (moderately hacky) check that creating ring proofs is indeed constant-time w.r.t. choices
    // in rings.
    const CHOICES: &[(&str, Option<[usize; 5]>)] = &[
        ("zeros", Some([0; 5])),
        ("ones", Some([1; 5])),
        ("max_values", Some([3; 5])),
        ("diagonal", Some([0, 1, 2, 3, 0])),
        ("random", None),
    ];
    for &(name, values) in CHOICES {
        group.bench_with_input(
            BenchmarkId::new("ring_timings", name),
            &values,
            |b, &values| bench_ring::<G>(b, values),
        );
    }
}

fn bench_edwards(criterion: &mut Criterion) {
    bench_group::<Curve25519Subgroup>(&mut criterion.benchmark_group("edwards"));
}

fn bench_ristretto(criterion: &mut Criterion) {
    bench_group::<Ristretto>(&mut criterion.benchmark_group("ristretto"));
}

fn bench_helpers<G: Group>(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.throughput(Throughput::Elements(1));

    let mut rng = ChaChaRng::from_seed([7; 32]);
    let point = G::mul_base_point(&G::generate_scalar(&mut rng));
    let challenge = G::generate_scalar(&mut rng);
    let response = G::generate_scalar(&mut rng);

    // `naive` method seems to be faster (probably due to use of the basepoint
    // multiplication table).
    group.bench_function("double_scalar_mul_basepoint/naive", |b| {
        b.iter(|| G::mul_base_point(&response) - point * &challenge)
    });
    group.bench_function("double_scalar_mul_basepoint/multi", |b| {
        b.iter(|| {
            G::multi_mul(
                [response, challenge].iter(),
                [G::base_point(), point].iter().copied(),
            )
        })
    });

    let other_point = G::mul_base_point(&G::generate_scalar(&mut rng));
    // As expected, `multi` implementation is faster than the naive one.
    group.bench_function("double_scalar_mul/naive", move |b| {
        b.iter(|| other_point * &response - point * &challenge)
    });
    group.bench_function("double_scalar_mul/multi", move |b| {
        b.iter(|| {
            G::multi_mul(
                [response, challenge].iter(),
                [other_point, point].iter().copied(),
            )
        })
    });
}

fn bench_edwards_helpers(criterion: &mut Criterion) {
    bench_helpers::<Curve25519Subgroup>(&mut criterion.benchmark_group("edwards"));
}

fn bench_ristretto_helpers(criterion: &mut Criterion) {
    bench_helpers::<Ristretto>(&mut criterion.benchmark_group("ristretto"));
}

criterion_group!(
    benches,
    bench_edwards_helpers,
    bench_ristretto_helpers,
    bench_edwards,
    bench_ristretto,
);
criterion_main!(benches);
