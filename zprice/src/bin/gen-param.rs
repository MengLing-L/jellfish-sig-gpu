
use ark_bn254::{Bn254, FrParameters,Fr};
use ark_ff::Fp256;
use ark_std::rand::{CryptoRng, RngCore};
use jf_plonk::{prelude::*, errors::CircuitError, circuit::Variable};
use jf_primitives::{signatures::schnorr::{VerKey, Signature, KeyPair}, circuit::signature::schnorr::SignatureGadget, constants::CS_ID_SCHNORR};
use jf_rescue::RescueParameter;

use ark_ed_on_bn254::EdwardsParameters as Param254;
use ark_ec::{
    group::Group,
    twisted_edwards_extended::{GroupAffine, GroupProjective},
    AffineCurve, ModelParameters, ProjectiveCurve, TEModelParameters as Parameters,
};
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
fn main() {
    let mut rng = rand::thread_rng();
    // let circuit = jf_zprice::generate_circuit(&mut rng).unwrap();
    let circuit: PlonkCircuit<Fr> = gen_circuit_for_bench::<_, Param254>().unwrap();
    let max_degree = circuit.srs_size().unwrap();

    // store SRS
    jf_zprice::store_srs(max_degree, None);

    // store proving key and verification key
    let srs = jf_zprice::load_srs(None);
    jf_zprice::store_proving_and_verification_key(srs, None, None);

    // just making sure they can be loaded
    jf_zprice::load_proving_key(None);
    jf_zprice::load_verification_key(None);
}
