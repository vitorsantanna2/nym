use itertools::izip;

use crate::error::CompactEcashError;
use crate::scheme::keygen::{
    generate_keypair_user, ttp_keygen, PublicKeyUser, SecretKeyUser, VerificationKeyAuth,
};
use crate::scheme::setup::Parameters;
use crate::scheme::withdrawal::{issue_verify, issue_wallet, withdrawal_request};
use crate::scheme::Wallet;
use crate::VerificationKey;

#[test]
fn main() -> Result<(), CompactEcashError> {
    let params = Parameters::new().unwrap();
    let user_keypair = generate_keypair_user(&params);

    let (req, req_info) = withdrawal_request(&params, &user_keypair.secret_key()).unwrap();
    let authorities_keypairs = ttp_keygen(&params, 2, 3).unwrap();

    let verification_keys_auth: Vec<VerificationKeyAuth> = authorities_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    let mut wallet_blinded_signatures = Vec::new();
    for auth_keypair in authorities_keypairs {
        let blind_signature = issue_wallet(
            &params,
            auth_keypair.secret_key(),
            user_keypair.public_key(),
            &req,
        );
        wallet_blinded_signatures.push(blind_signature.unwrap());
    }

    let unblinded_wallet_shares: Vec<Wallet> = izip!(
        wallet_blinded_signatures.iter(),
        verification_keys_auth.iter()
    )
    .map(|(w, vk)| issue_verify(&params, vk, &user_keypair.secret_key(), w, &req_info).unwrap())
    .collect();

    Ok(())
}
