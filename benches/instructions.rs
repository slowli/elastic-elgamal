use elastic_elgamal::{
    Keypair,
    elliptic_curve::rand_core::SeedableRng,
    group::{Curve25519Subgroup, Generic, Group, Ristretto},
};
use rand_chacha::ChaChaRng;
use yab::{BenchmarkId, captures};

trait BenchmarkedGroup: Group {
    const NAME: &'static str;
}

impl BenchmarkedGroup for Ristretto {
    const NAME: &'static str = "ristretto";
}

impl BenchmarkedGroup for Curve25519Subgroup {
    const NAME: &'static str = "curve25519";
}

impl BenchmarkedGroup for Generic<k256::Secp256k1> {
    const NAME: &'static str = "k256";
}

fn bench_group<G: BenchmarkedGroup>(bencher: &mut yab::Bencher) {
    let group = G::NAME;
    bencher.bench_with_captures(
        group,
        captures!(|[encrypt, decrypt]| {
            let mut rng = ChaChaRng::from_seed([5; 32]);
            let keypair: Keypair<G> = Keypair::generate(&mut rng);
            let message = G::generate_scalar(&mut rng);
            let ciphertext = encrypt.measure(|| keypair.public().encrypt(message, &mut rng));
            decrypt.measure(|| keypair.secret().decrypt_to_element(ciphertext));
        }),
    );

    bencher.bench_with_captures(
        format!("{group}/zero"),
        captures!(|[prove, verify]| {
            let mut rng = ChaChaRng::from_seed([5; 32]);
            let keypair: Keypair<G> = Keypair::generate(&mut rng);
            let (ciphertext, proof) = prove.measure(|| keypair.public().encrypt_zero(&mut rng));
            verify
                .measure(|| keypair.public().verify_zero(ciphertext, &proof))
                .unwrap()
        }),
    );

    for val in [false, true] {
        bencher.bench_with_captures(
            BenchmarkId::new(format!("{group}/bool"), val),
            captures!(|[prove, verify]| {
                let mut rng = ChaChaRng::from_seed([5; 32]);
                let keypair: Keypair<G> = Keypair::generate(&mut rng);
                let (ciphertext, proof) =
                    prove.measure(|| keypair.public().encrypt_bool(val, &mut rng));
                verify
                    .measure(|| keypair.public().verify_bool(ciphertext, &proof))
                    .unwrap();
            }),
        );
    }
}

fn benches(bencher: &mut yab::Bencher) {
    bench_group::<Generic<k256::Secp256k1>>(bencher);
    bench_group::<Ristretto>(bencher);
    bench_group::<Curve25519Subgroup>(bencher);
}

yab::main!(benches);
