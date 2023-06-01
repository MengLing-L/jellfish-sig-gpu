
use std::time::Instant;

use ark_bn254::{Bn254, FrParameters,Fr};
use ark_ff::Fp256;
use ark_std::rand::{CryptoRng, RngCore};
use criterion::{criterion_group, criterion_main, Criterion};
use jf_plonk::{prelude::*, errors::CircuitError, circuit::Variable};
use jf_primitives::{signatures::schnorr::{VerKey, Signature, KeyPair}, circuit::signature::schnorr::SignatureGadget, constants::CS_ID_SCHNORR};
use jf_rescue::RescueParameter;
use ark_ec::{
    group::Group,
    twisted_edwards_extended::{GroupAffine, GroupProjective},
    AffineCurve, ModelParameters, ProjectiveCurve, TEModelParameters as Parameters,
};

use ark_ed_on_bn254::EdwardsParameters as Param254;
const NUM_REPETITIONS: usize = 50;

fn prove<C, R>(
    rng: &mut R,
    circuit: &C,
    prove_key: &ProvingKey<Bn254>,
) -> Result<Proof<Bn254>, PlonkError>
where
    C: Arithmetization<Fr>,
    R: CryptoRng + RngCore,
{
    // TODO: USE THIS DURING ACTUAL BENCHMARK
    prover_single_gpu::Prover::prove(rng, circuit, &prove_key)
    // PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(rng, circuit, &prove_key)
}

pub fn build_verify_sig_circuit<F, P>(
    vk: &VerKey<P>,
    msg: &[F],
    sig: &Signature<P>,
) -> Result<PlonkCircuit<F>, CircuitError>
where
    F: RescueParameter,
    P: Parameters<BaseField = F> + Clone,
{
    let mut circuit = PlonkCircuit::<F>::new();
    let vk_var = circuit.create_signature_vk_variable(vk).unwrap();
    let sig_var = circuit.create_signature_variable(sig).unwrap();
    let msg_var: Vec<Variable> = msg
        .iter()
        .map(|m| circuit.create_variable(*m))
        .collect::<Result<Vec<_>, PlonkError>>().unwrap();
    SignatureGadget::<F, P>::verify_signature(&mut circuit, &vk_var, &msg_var, &sig_var).unwrap();
    Ok(circuit)
}

fn gen_circuit_for_bench<F, P>() -> Result<PlonkCircuit<F>, PlonkError> 
where
    F: RescueParameter,
    P: Parameters<BaseField = F> + Clone,
{
    let mut rng = ark_std::test_rng();
    let keypair = KeyPair::<P>::generate(&mut rng);
    let vk = keypair.ver_key_ref();
    let vk_bad: VerKey<P> = KeyPair::<P>::generate(&mut rng).ver_key_ref().clone();
    let msg: Vec<F> = (0..20).map(|i| F::from(i as u64)).collect();
    let mut msg_bad = msg.clone();
    msg_bad[0] = F::from(2 as u64);
    let sig = keypair.sign(&msg, CS_ID_SCHNORR);
    let sig_bad = keypair.sign(&msg_bad, CS_ID_SCHNORR);
    vk.verify(&msg, &sig, CS_ID_SCHNORR).unwrap();

    // Test `verify_signature()`
    // Good path
    let mut circuit: PlonkCircuit<F> = build_verify_sig_circuit(vk, &msg, &sig)?;
    //Finalize the circuit.
    assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
    circuit.finalize_for_arithmetization()?;

    // println!("{:?}",cs.srs_size());

    Ok(circuit)
}

pub fn criterion_benchmark()
{
    let mut rng = rand::thread_rng();

    // Build a circuit with randomly sampled satisfying assignments
    // let circuit = jf_zprice::generate_circuit(&mut rng).unwrap();
    let circuit: PlonkCircuit<Fr> = gen_circuit_for_bench::<_, Param254>().unwrap();

    // load pre-generated proving key and verification key from files
    let pk = jf_zprice::load_proving_key(None);
    let vk = jf_zprice::load_verification_key(None);

    // verify the proof against the public inputs.
    let start = Instant::now();
    for _ in 0..NUM_REPETITIONS {
        let _ = prove(&mut rng, &circuit, &pk).unwrap();
    }

    println!(
        "{} times proving time for {}: {} ns",
        // stringify!($bench_curve),
        NUM_REPETITIONS,
        "signature",
        start.elapsed().as_nanos()  as u128
    );


    let proof = prove(&mut rng, &circuit, &pk).unwrap();
    let public_inputs = circuit.public_input().unwrap();
    let start = Instant::now();
    for _ in 0..NUM_REPETITIONS {
        let _ =PlonkKzgSnark::<Bn254>::verify::<StandardTranscript>(&vk, &public_inputs, &proof,).unwrap();
    }
    println!(
        "{} times verifing time for {}: {} ns",
        // stringify!($bench_curve),
        NUM_REPETITIONS,
        "signature",
        start.elapsed().as_nanos()  as u128
    );

    assert!(
        PlonkKzgSnark::<Bn254>::verify::<StandardTranscript>(&vk, &public_inputs, &proof,)
            .is_ok()
    );

    // c.bench_function("TurboPlonk Prover", |b| {
    //     b.iter(|| prove(&mut rng, &circuit, &pk).unwrap())
    // });
}

// criterion_group!(
//     name = benches;
//     config = Criterion::default().sample_size(10);
//     targets = criterion_benchmark
// );
// criterion_main!(benches);

fn main() {
    criterion_benchmark();
    // bench_batch_verify();
}
