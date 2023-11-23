use std::collections::HashMap;
use std::ops::Index;

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar};
use group::{Curve, GroupEncoding};
use ff::Field;
use rand::thread_rng;

use crate::error::{CompactEcashError, Result};
use crate::utils::{hash_g1, Signature};
use crate::scheme::keygen::{SecretKeyAuth, VerificationKeyAuth};
use crate::constants;
use rayon::prelude::*;
use crate::utils::{check_bilinear_pairing, generate_lagrangian_coefficients_at_origin};


pub struct GroupParameters {
    /// Generator of the G1 group
    g1: G1Affine,
    /// Generator of the G2 group
    g2: G2Affine,
    /// Additional generators of the G1 group
    gammas: Vec<G1Projective>,
    // Additional generator of the G1 group
    delta: G1Projective,
    /// Precomputed G2 generator used for the miller loop
    _g2_prepared_miller: G2Prepared,
}

impl GroupParameters {
    pub fn new() -> Result<GroupParameters> {
        let gammas = (1..=constants::ATTRIBUTES_LEN)
            .map(|i| hash_g1(format!("gamma{}", i)))
            .collect();

        let delta = hash_g1("delta");

        Ok(GroupParameters {
            g1: G1Affine::generator(),
            g2: G2Affine::generator(),
            gammas,
            delta,
            _g2_prepared_miller: G2Prepared::from(G2Affine::generator()),
        })
    }

    pub(crate) fn gen1(&self) -> &G1Affine {
        &self.g1
    }

    pub(crate) fn gen2(&self) -> &G2Affine {
        &self.g2
    }

    pub(crate) fn gammas(&self) -> &Vec<G1Projective> {
        &self.gammas
    }

    pub(crate) fn gamma_idx(&self, i: usize) -> Option<&G1Projective>{
        self.gammas.get(i)
    }

    pub(crate) fn delta(&self) -> &G1Projective { &self.delta }

    pub fn random_scalar(&self) -> Scalar {
        // lazily-initialized thread-local random number generator, seeded by the system
        let mut rng = thread_rng();
        Scalar::random(&mut rng)
    }

    pub fn n_random_scalars(&self, n: usize) -> Vec<Scalar> {
        (0..n).map(|_| self.random_scalar()).collect()
    }

    pub(crate) fn prepared_miller_g2(&self) -> &G2Prepared {
        &self._g2_prepared_miller
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct SecretKeyRP {
    pub(crate) x: Scalar,
    pub(crate) y: Scalar,
}

impl SecretKeyRP {
    pub fn public_key(&self, params: &GroupParameters) -> PublicKeyRP {
        PublicKeyRP {
            alpha: params.gen2() * self.x,
            beta: params.gen2() * self.y,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PublicKeyRP {
    pub(crate) alpha: G2Projective,
    pub(crate) beta: G2Projective,
}

pub struct Parameters {
    /// group parameters
    grp: GroupParameters,
    /// Public Key for range proof verification
    pk_rp: PublicKeyRP,
    /// Max value of wallet
    L: u64,
    /// list of signatures for values l in [0, L]
    signs: HashMap<u64, Signature>,
}

impl Parameters {
    pub fn grp(&self) -> &GroupParameters {
        &self.grp
    }
    pub fn pk_rp(&self) -> &PublicKeyRP {
        &self.pk_rp
    }
    pub fn L(&self) -> u64 {
        self.L
    }
    pub fn signs(&self) -> &HashMap<u64, Signature> {
        &self.signs
    }
    pub fn get_sign_by_idx(&self, idx: u64) -> Result<&Signature> {
        match self.signs.get(&idx) {
            Some(val) => return Ok(val),
            None => {
                return Err(CompactEcashError::RangeProofOutOfBound(
                    "Cannot find the range proof signature for the given value. \
                        Check if the requested value is within the bound 0..L"
                        .to_string(),
                ));
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct CoinIndexSignature{
    pub(crate) h : G1Projective,
    pub(crate) s : G1Projective,
}

pub type PartialCoinIndexSignature = CoinIndexSignature;

pub fn sign_coin_indices(params: &Parameters, vk: &VerificationKeyAuth, sk_auth: &SecretKeyAuth) -> Vec<PartialCoinIndexSignature>{
    let m1: Scalar = Scalar::from_bytes(&constants::TYPE_IDX).unwrap();
    let m2: Scalar = Scalar::from_bytes(&constants::TYPE_IDX).unwrap();
    let mut partial_coins_signatures = Vec::with_capacity(params.L() as usize);

    for l in 0..params.L(){
        let m0: Scalar = Scalar::from(l as u64);
        // Compute the hash h
        let mut concatenated_bytes = Vec::with_capacity(vk.to_bytes().len() + l.to_le_bytes().len());
        concatenated_bytes.extend_from_slice(&vk.to_bytes());
        concatenated_bytes.extend_from_slice(&l.to_le_bytes());
        let h = hash_g1(concatenated_bytes);

        // Sign the attributes by performing scalar-point multiplications and accumulating the result
        let mut s_exponent = sk_auth.x;
        s_exponent += &sk_auth.ys[0] * m0;
        s_exponent += &sk_auth.ys[1] * m1;
        s_exponent += &sk_auth.ys[2] * m2;
        // Create the signature struct of on the coin index
        let coin_idx_sign = CoinIndexSignature{
            h,
            s: h * s_exponent,
        };
        partial_coins_signatures.push(coin_idx_sign);
    }
    partial_coins_signatures
}

pub fn verify_coin_indices_signatures(
    params: &Parameters,
    vk: &VerificationKeyAuth,
    vk_auth: &VerificationKeyAuth,
    signatures: &[CoinIndexSignature],
) -> Result<()>{
    let m1: Scalar = Scalar::from_bytes(&constants::TYPE_IDX).unwrap();
    let m2: Scalar = Scalar::from_bytes(&constants::TYPE_IDX).unwrap();
    for (l, sig) in signatures.iter().enumerate() {
        let m0: Scalar = Scalar::from(l as u64);
        // Compute the hash h
        let mut concatenated_bytes = Vec::with_capacity(vk.to_bytes().len() + l.to_le_bytes().len());
        concatenated_bytes.extend_from_slice(&vk.to_bytes());
        concatenated_bytes.extend_from_slice(&l.to_le_bytes());
        let h = hash_g1(concatenated_bytes);
        // Check if the hash is matching
        if sig.h != h {
            return Err(CompactEcashError::CoinIndices(
                "Failed to verify the commitment hash".to_string(),
            ));
        }
        let partially_signed_attributes = [m0, m1, m2]
            .iter()
            .zip(vk_auth.beta_g2.iter())
            .map(|(m, beta_i)| beta_i * Scalar::from(*m))
            .sum::<G2Projective>();
        if !check_bilinear_pairing(
            &sig.h.to_affine(),
            &G2Prepared::from((vk_auth.alpha + partially_signed_attributes).to_affine()),
            &sig.s.to_affine(),
            params.grp().prepared_miller_g2(),
        ) {
            return Err(CompactEcashError::CoinIndices(
                "Verification of the coin signature failed".to_string(),
            ));
        }
    }
    Ok(())

}

pub fn aggregate_indices_signatures(params: Parameters, vk: &VerificationKeyAuth, signatures: &[(u64, VerificationKeyAuth, Vec<PartialCoinIndexSignature>)]){
    // Check if all indices are unique
    // if signatures.iter().map(|(index, _, _)| index).unique().count() != signatures.len() {
    //     return Err(CompactEcashError::CoinIndices(
    //         "Not enough unique indices shares".to_string(),
    //     ));
    // }
    // Evaluate at 0 the Lagrange basis polynomials k_i
    let coefficients = generate_lagrangian_coefficients_at_origin(&signatures.iter().map(|(index, _, _)| *index).collect::<Vec<_>>());
    let m1: Scalar = Scalar::from_bytes(&constants::TYPE_IDX).unwrap();
    let m2: Scalar = Scalar::from_bytes(&constants::TYPE_IDX).unwrap();
    for l in 0..params.L(){
        let m0: Scalar = Scalar::from(l);
        // Compute the hash h
        let mut concatenated_bytes = Vec::with_capacity(vk.to_bytes().len() + l.to_le_bytes().len());
        concatenated_bytes.extend_from_slice(&vk.to_bytes());
        concatenated_bytes.extend_from_slice(&l.to_le_bytes());
        let h = hash_g1(concatenated_bytes);
        for (i, vk_auth, sig) in signatures.iter(){

        }
    }

}

pub fn setup(L: u64) -> Parameters {
    let grp = GroupParameters::new().unwrap();
    let x = grp.random_scalar();
    let y = grp.random_scalar();
    let sk_rp = SecretKeyRP { x, y };
    let pk_rp = sk_rp.public_key(&grp);
    let mut signs = HashMap::new();
    for l in 0..L {
        let r = grp.random_scalar();
        let h = grp.gen1() * r;
        signs.insert(
            l,
            Signature {
                0: h,
                1: h * (x + y * Scalar::from(l)),
            },
        );
    }
    Parameters {
        grp,
        pk_rp,
        L,
        signs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::keygen::{ttp_keygen};
    use crate::scheme::aggregation::aggregate_verification_keys;

    #[test]
    fn test_sign_coins(){
        let L = 32;
        let params = setup(L);
        let authorities_keypairs = ttp_keygen(&params.grp(), 2, 3).unwrap();
        let indices: [u64; 3] = [1, 2, 3];

        // Pick one authority to do the signing
        let sk_i_auth = authorities_keypairs[0].secret_key();
        let vk_i_auth = authorities_keypairs[0].verification_key();

        // list of verification keys of each authority
        let verification_keys_auth: Vec<VerificationKeyAuth> = authorities_keypairs
            .iter()
            .map(|keypair| keypair.verification_key())
            .collect();
        // the global master verification key
        let verification_key = aggregate_verification_keys(&verification_keys_auth, Some(&indices)).unwrap();

        let partial_signatures = sign_coin_indices(&params, &verification_key, &sk_i_auth);
        assert!(verify_coin_indices_signatures(&params, &verification_key, &vk_i_auth, &partial_signatures).is_ok());

    }
}