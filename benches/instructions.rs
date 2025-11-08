use elastic_elgamal::{
    Keypair,
    elliptic_curve::rand_core::SeedableRng,
    group::{Curve25519Subgroup, Generic, Group, Ristretto},
};
use rand_chacha::ChaChaRng;

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
    bencher.bench_with_capture(format!("{group}/encrypt"), |capture| {
        let mut rng = ChaChaRng::from_seed([5; 32]);
        let keypair: Keypair<G> = Keypair::generate(&mut rng);
        let message = G::generate_scalar(&mut rng);
        capture.measure(|| keypair.public().encrypt(message, &mut rng));
    });

    bencher.bench_with_capture(format!("{group}/decrypt"), |capture| {
        let mut rng = ChaChaRng::from_seed([5; 32]);
        let keypair: Keypair<G> = Keypair::generate(&mut rng);
        let message = G::generate_scalar(&mut rng);
        let ciphertext = keypair.public().encrypt(message, &mut rng);
        capture.measure(|| keypair.secret().decrypt_to_element(ciphertext));
    });

    bencher.bench_with_capture(format!("{group}/zero_prove"), |capture| {
        let mut rng = ChaChaRng::from_seed([5; 32]);
        let keypair: Keypair<G> = Keypair::generate(&mut rng);
        capture.measure(|| keypair.public().encrypt_zero(&mut rng));
    });

    bencher.bench_with_capture(format!("{group}/zero_verify"), |capture| {
        let mut rng = ChaChaRng::from_seed([5; 32]);
        let keypair: Keypair<G> = Keypair::generate(&mut rng);
        let (ciphertext, proof) = keypair.public().encrypt_zero(&mut rng);
        capture
            .measure(|| keypair.public().verify_zero(ciphertext, &proof))
            .unwrap();
    });

    for val in [false, true] {
        bencher.bench_with_capture(format!("{group}/bool_prove/{val}"), |capture| {
            let mut rng = ChaChaRng::from_seed([5; 32]);
            let keypair: Keypair<G> = Keypair::generate(&mut rng);
            capture.measure(|| keypair.public().encrypt_bool(val, &mut rng));
        });

        bencher.bench_with_capture(format!("{group}/bool_verify/{val}"), |capture| {
            let mut rng = ChaChaRng::from_seed([5; 32]);
            let keypair: Keypair<G> = Keypair::generate(&mut rng);
            let (ciphertext, proof) = keypair.public().encrypt_bool(val, &mut rng);
            capture
                .measure(|| keypair.public().verify_bool(ciphertext, &proof))
                .unwrap();
        });
    }
}

fn benches(bencher: &mut yab::Bencher) {
    bench_group::<Generic<k256::Secp256k1>>(bencher);
    bench_group::<Ristretto>(bencher);
    bench_group::<Curve25519Subgroup>(bencher);
}

yab::main!(benches);
