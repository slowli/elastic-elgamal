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
    bencher.bench_with_capture(format!("{}/encrypt", G::NAME), |capture| {
        let mut rng = ChaChaRng::from_seed([5; 32]);
        let keypair: Keypair<G> = Keypair::generate(&mut rng);
        let message = G::generate_scalar(&mut rng);
        capture.measure(|| keypair.public().encrypt(message, &mut rng));
    });

    bencher.bench_with_capture(format!("{}/decrypt", G::NAME), |capture| {
        let mut rng = ChaChaRng::from_seed([5; 32]);
        let keypair: Keypair<G> = Keypair::generate(&mut rng);
        let message = G::generate_scalar(&mut rng);
        let ciphertext = keypair.public().encrypt(message, &mut rng);
        capture.measure(|| keypair.secret().decrypt_to_element(ciphertext));
    });
}

fn benches(bencher: &mut yab::Bencher) {
    bench_group::<Generic<k256::Secp256k1>>(bencher);
    bench_group::<Ristretto>(bencher);
    bench_group::<Curve25519Subgroup>(bencher);
}

yab::main!(benches);
