use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, Bencher, BenchmarkGroup,
    BenchmarkId, Criterion, Throughput,
};
use merlin::Transcript;
use rand::{seq::SliceRandom, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use elastic_elgamal::{
    app::{QuadraticVotingBallot, QuadraticVotingParams},
    group::{Curve25519Subgroup, Generic, Group, Ristretto},
    CiphertextWithValue, Keypair, RingProofBuilder, SumOfSquaresProof,
};

type K256 = Generic<k256::Secp256k1>;

fn bench_encrypt<G: Group>(b: &mut Bencher<'_>) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    let message = G::generate_scalar(&mut rng);
    b.iter(|| keypair.public().encrypt(message, &mut rng));
}

fn bench_decrypt<G: Group>(b: &mut Bencher<'_>) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    let message = G::generate_scalar(&mut rng);
    b.iter_batched(
        || keypair.public().encrypt(message, &mut rng),
        |encrypted| keypair.secret().decrypt_to_element(encrypted),
        BatchSize::SmallInput,
    );
}

fn bench_zero_encryption_proof<G: Group>(b: &mut Bencher<'_>) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter(|| keypair.public().encrypt_zero(&mut rng));
}

fn bench_zero_encryption_verification<G: Group>(b: &mut Bencher<'_>) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter_batched(
        || keypair.public().encrypt_zero(&mut rng),
        |(ciphertext, proof)| keypair.public().verify_zero(ciphertext, &proof).unwrap(),
        BatchSize::SmallInput,
    );
}

fn bench_bool_encryption_proof<G: Group>(b: &mut Bencher<'_>) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter(|| keypair.public().encrypt_bool(rng.gen_bool(0.5), &mut rng));
}

fn bench_bool_encryption_verification<G: Group>(b: &mut Bencher<'_>) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter_batched(
        || keypair.public().encrypt_bool(rng.gen_bool(0.5), &mut rng),
        |(ciphertext, proof)| keypair.public().verify_bool(ciphertext, &proof).unwrap(),
        BatchSize::SmallInput,
    );
}

fn bench_choice_creation<G: Group>(b: &mut Bencher<'_>, number_of_variants: usize) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter(|| {
        let choice = rng.gen_range(0..number_of_variants);
        keypair
            .public()
            .encrypt_choice(number_of_variants, choice, &mut rng)
    });
}

fn bench_choice_verification<G: Group>(b: &mut Bencher<'_>, number_of_variants: usize) {
    let mut rng = ChaChaRng::from_seed([5; 32]);
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter_batched(
        || {
            let choice = rng.gen_range(0..number_of_variants);
            keypair
                .public()
                .encrypt_choice(number_of_variants, choice, &mut rng)
        },
        |encrypted| {
            keypair.public().verify_choice(&encrypted).unwrap();
        },
        BatchSize::SmallInput,
    );
}

fn bench_qv_creation<G: Group>(b: &mut Bencher<'_>) {
    let mut rng = ChaChaRng::from_seed([7; 32]);
    let params = QuadraticVotingParams::new(4, 30);
    let mut votes = [4, 0, 3, 1];
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter(|| {
        votes.shuffle(&mut rng);
        QuadraticVotingBallot::new(&params, &votes, keypair.public(), &mut rng)
    });
}

fn bench_qv_verification<G: Group>(b: &mut Bencher<'_>) {
    let mut rng = ChaChaRng::from_seed([7; 32]);
    let params = QuadraticVotingParams::new(4, 30);
    let mut votes = [4, 0, 3, 1];
    let keypair: Keypair<G> = Keypair::generate(&mut rng);
    b.iter_batched(
        || {
            votes.shuffle(&mut rng);
            QuadraticVotingBallot::new(&params, &votes, keypair.public(), &mut rng)
        },
        |ballot| {
            drop(ballot.verify(&params, keypair.public()).unwrap());
        },
        BatchSize::SmallInput,
    );
}

fn bench_ring<G: Group>(b: &mut Bencher<'_>, chosen_values: Option<[usize; 5]>) {
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
        G::generator(),
        G::generator() + G::generator(),
        G::generator() + G::generator() + G::generator(),
    ];
    b.iter(|| {
        let mut transcript = Transcript::new(b"bench_ring");
        let mut ring_responses = [G::Scalar::default(); 20];
        let mut builder =
            RingProofBuilder::new(&receiver, 5, &mut ring_responses, &mut transcript, &mut rng);
        for &value_index in &chosen_values {
            builder.add_value(&admissible_values, value_index);
        }
        builder.build()
    });
}

fn bench_sum_sq_creation<G: Group>(b: &mut Bencher<'_>, len: usize) {
    let mut rng = ChaChaRng::from_seed([121; 32]);
    let (receiver, _) = Keypair::<G>::generate(&mut rng).into_tuple();

    let values: Vec<_> = (0..len).map(|_| rng.gen_range(0_u64..10)).collect();
    let sum_sq = values.iter().map(|&x| x * x).sum::<u64>();
    let values: Vec<_> = values
        .into_iter()
        .map(|x| CiphertextWithValue::new(x, &receiver, &mut rng))
        .collect();
    let sum_sq = CiphertextWithValue::new(sum_sq, &receiver, &mut rng);

    b.iter(|| {
        let mut transcript = Transcript::new(b"bench_sum_of_squares");
        SumOfSquaresProof::new(values.iter(), &sum_sq, &receiver, &mut transcript, &mut rng)
    })
}

fn bench_sum_sq_verification<G: Group>(b: &mut Bencher<'_>, len: usize) {
    let mut rng = ChaChaRng::from_seed([121; 32]);
    let (receiver, _) = Keypair::<G>::generate(&mut rng).into_tuple();

    let values: Vec<_> = (0..len).map(|_| rng.gen_range(0_u64..10)).collect();
    let sum_sq = values.iter().map(|&x| x * x).sum::<u64>();
    let values: Vec<_> = values
        .into_iter()
        .map(|x| CiphertextWithValue::new(x, &receiver, &mut rng))
        .collect();
    let sum_sq = CiphertextWithValue::new(sum_sq, &receiver, &mut rng);

    b.iter_batched(
        || {
            let mut transcript = Transcript::new(b"bench_sum_of_squares");
            SumOfSquaresProof::new(values.iter(), &sum_sq, &receiver, &mut transcript, &mut rng)
        },
        |proof| {
            proof.verify(
                values.iter().map(CiphertextWithValue::inner),
                sum_sq.inner(),
                &receiver,
                &mut Transcript::new(b"bench_sum_of_squares"),
            )
        },
        BatchSize::SmallInput,
    )
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

    group
        .bench_function("qv_prove", bench_qv_creation::<G>)
        .bench_function("qv_verify", bench_qv_verification::<G>);
    for &choice_size in CHOICE_SIZES {
        group.bench_with_input(
            BenchmarkId::new("sum_sq_prove", choice_size),
            &choice_size,
            |b, &size| bench_sum_sq_creation::<G>(b, size),
        );
    }
    for &choice_size in CHOICE_SIZES {
        group.bench_with_input(
            BenchmarkId::new("sum_sq_verify", choice_size),
            &choice_size,
            |b, &size| bench_sum_sq_verification::<G>(b, size),
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

fn bench_curve25519(criterion: &mut Criterion) {
    bench_group::<Curve25519Subgroup>(&mut criterion.benchmark_group("curve25519"));
}

fn bench_ristretto(criterion: &mut Criterion) {
    bench_group::<Ristretto>(&mut criterion.benchmark_group("ristretto"));
}

fn bench_k256(criterion: &mut Criterion) {
    bench_group::<K256>(&mut criterion.benchmark_group("k256"));
}

fn bench_helpers<G: Group>(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.throughput(Throughput::Elements(1));

    let mut rng = ChaChaRng::from_seed([7; 32]);
    let element = G::mul_generator(&G::generate_scalar(&mut rng));
    let challenge = G::generate_scalar(&mut rng);
    let response = G::generate_scalar(&mut rng);

    // `naive` method seems to be faster for `Curve25519Subgroup` / `Ristretto`
    // (probably due to use of the dedicated basepoint multiplication tables).
    group.bench_function("double_scalar_mul_generator/naive", |b| {
        b.iter(|| G::mul_generator(&response) - element * &challenge)
    });
    group.bench_function("double_scalar_mul_generator/multi", |b| {
        b.iter(|| {
            G::multi_mul(
                [response, challenge].iter(),
                [G::generator(), element].iter().copied(),
            )
        })
    });

    let other_element = G::mul_generator(&G::generate_scalar(&mut rng));
    // As expected, `multi` implementation is faster than the naive one.
    group.bench_function("double_scalar_mul/naive", move |b| {
        b.iter(|| other_element * &response - element * &challenge)
    });
    group.bench_function("double_scalar_mul/multi", move |b| {
        b.iter(|| {
            G::multi_mul(
                [response, challenge].iter(),
                [other_element, element].iter().copied(),
            )
        })
    });
}

fn bench_curve25519_helpers(criterion: &mut Criterion) {
    bench_helpers::<Curve25519Subgroup>(&mut criterion.benchmark_group("curve25519"));
}

fn bench_ristretto_helpers(criterion: &mut Criterion) {
    bench_helpers::<Ristretto>(&mut criterion.benchmark_group("ristretto"));
}

fn bench_k256_helpers(criterion: &mut Criterion) {
    bench_helpers::<K256>(&mut criterion.benchmark_group("k256"));
}

criterion_group!(
    benches,
    bench_curve25519_helpers,
    bench_ristretto_helpers,
    bench_k256_helpers,
    bench_curve25519,
    bench_ristretto,
    bench_k256,
);
criterion_main!(benches);
