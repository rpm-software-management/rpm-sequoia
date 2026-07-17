use std::time::SystemTime;

use sequoia_openpgp as openpgp;
use openpgp::crypto::mpi;
use openpgp::packet::Signature;
use openpgp::policy::AsymmetricAlgorithm;
use openpgp::policy::StandardPolicy;

/// Determines whether a signature is acceptable according to the
/// policy.
///
/// A signature includes the signer's alleged public key algorithm,
/// but this is not always enough to decide whether the key is
/// acceptable by a policy.  Algorithms like RSA have different
/// policies depending on the key size.  Some ECC algorithms have a
/// single algorithm and are distinguished based on a curve parameter,
/// which is not included in the signature.
///
/// This function determines the set of public key algorithms that
/// could have been used to generate the signature.  If the policy
/// rejects all of the algorithms, then we know that the key would be
/// rejected by the policy.  Otherwise we conservatively accept the
/// signature.
pub fn policy_check_signature(policy: &StandardPolicy, time: SystemTime,
                              sig: &Signature)
    -> std::result::Result<(), anyhow::Error>
{
    tracer!(*crate::TRACE, "policy_check_signature");

    let candidates = match sig.mpis() {
        mpi::Signature::RSA { s } => {
            t!("RSA signature");

            // MPIs drop leading zeros, so a 2048-bit key might
            // produce a 2040-bit signature.  As such consider a
            // 2048-delta bit signature to be either a RSA1024 or a
            // RSA2048 signature.

            let bits = s.value().len() * 8;
            match bits {
                0..=2028 => &[ AsymmetricAlgorithm::RSA1024 ][..],
                2029..=2048 =>
                    &[ AsymmetricAlgorithm::RSA1024, AsymmetricAlgorithm::RSA2048 ],
                2049..=3052 =>
                    &[ AsymmetricAlgorithm::RSA2048 ],
                3053..=3072 =>
                    &[ AsymmetricAlgorithm::RSA2048, AsymmetricAlgorithm::RSA3072 ],
                3073..=4076 =>
                    &[ AsymmetricAlgorithm::RSA3072 ],
                4077..=4096 =>
                    &[ AsymmetricAlgorithm::RSA3072, AsymmetricAlgorithm::RSA4096 ],
                _ => &[ AsymmetricAlgorithm::RSA4096 ],
            }
        },
        mpi::Signature::DSA { r, .. } => {
            t!("DSA signature");

            // DSA signature sizes depend on 'q', not 'p'.
            // q=160 (1024-bit p), q=224 (2048-bit p), q=256 (3072-bit p)
            let q_bits = r.value().len() * 8;

            if q_bits <= 160 {
                &[ AsymmetricAlgorithm::DSA1024 ]
            } else if q_bits <= 224 {
                &[ AsymmetricAlgorithm::DSA2048 ]
            } else if q_bits <= 256 {
                &[ AsymmetricAlgorithm::DSA3072 ]
            } else {
                &[ AsymmetricAlgorithm::DSA4096 ]
            }
        },
        mpi::Signature::EdDSA { .. } => {
            t!("EdDSA signature");

            &[ AsymmetricAlgorithm::EdDSA ]
        },
        mpi::Signature::ECDSA { r, .. } => {
            let bytes = r.value().len();

            t!("ECDSA signature, {} bytes", bytes);

            // See: https://www.rfc-editor.org/rfc/rfc9580.html#section-9.2
            //
            // Recall: leading zeros are stripped.  Allow for a bit of
            // tolerance.
            match bytes {
                30..=32 => {
                    &[
                        AsymmetricAlgorithm::NistP256,
                        AsymmetricAlgorithm::BrainpoolP256,
                    ][..]
                }
                46..=48 => {
                    &[
                        AsymmetricAlgorithm::NistP384,
                        AsymmetricAlgorithm::BrainpoolP384,
                    ]
                }
                62..=64 => {
                    &[
                        AsymmetricAlgorithm::BrainpoolP512,
                    ]
                }
                65..=66 => {
                    &[
                        AsymmetricAlgorithm::NistP521,
                    ]
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "ECDSA with invalid r ({} bytes)", bytes));
                }
            }
        },
        mpi::Signature::Ed25519 { .. } => {
            t!("Ed25519 signature");

            &[ AsymmetricAlgorithm::Ed25519 ]
        },
        mpi::Signature::Ed448 { .. } => {
            t!("Ed448 signature");

            &[ AsymmetricAlgorithm::Ed448 ]
        },
        mpi::Signature::MLDSA65_Ed25519 { .. } => {
            t!("MLDSA65_Ed25519 signature");

            &[ AsymmetricAlgorithm::MLDSA65_Ed25519 ]
        },
        mpi::Signature::MLDSA87_Ed448 { .. } => {
            t!("MLDSA87_Ed448 signature");
            &[ AsymmetricAlgorithm::MLDSA87_Ed448 ]
        },
        mpi::Signature::SLHDSA128s { .. } => {
            t!("SLHDSA128s signature");
            &[ AsymmetricAlgorithm::SLHDSA128s ]
        },
        mpi::Signature::SLHDSA128f { .. } => {
            t!("SLHDSA128f signature");
            &[ AsymmetricAlgorithm::SLHDSA128f ]
        },
        mpi::Signature::SLHDSA256s { .. } => {
            t!("SLHDSA256s signature");
            &[ AsymmetricAlgorithm::SLHDSA256s ]
        },
        _ => {
            t!("Unhandled signature");
            return Err(anyhow::anyhow!("Not a known signing algorithm"));
        }
    };

    for candidate in candidates {
        t!("Candidate algorithm: {}", candidate);
    }

    // If the policy accepts any candidate algorithm, then the
    // signature may be allowed.  As such, don't reject.
    let mut err = None;
    for candidate in candidates {
        if let Some(cutoff)
            = policy.asymmetric_algo_cutoff(candidate.clone())
        {
            if time >= cutoff {
                t!("Candidate algorithm {} rejected by policy", candidate);
                if err.is_none() {
                    err = Some(openpgp::Error::PolicyViolation(
                        candidate.to_string(), Some(cutoff.into())).into());
                }
            } else {
                // Acceptable.
                t!("Candidate algorithm {} accepted by policy", candidate);
                return Ok(());
            }
        } else {
            // None => always secure.
            t!("Candidate algorithm {} accepted by policy", candidate);
            return Ok(());
        }
    }

    if let Some(err) = err {
        Err(err)
    } else {
        // No candidates.
        t!("Not a known signing algorithm");
        return Err(anyhow::anyhow!("Not a known signing algorithm"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use openpgp::Packet;
    use openpgp::Profile;
    use openpgp::cert::CertBuilder;
    use openpgp::parse::Parse;
    use openpgp::serialize::stream::Message;
    use openpgp::serialize::stream::Signer;
    use openpgp::types::KeyFlags;
    use openpgp::types::PublicKeyAlgorithmSpecification;

    fn reject_all_except(except: &[AsymmetricAlgorithm])
        -> StandardPolicy<'static>
    {
        let mut p = StandardPolicy::new();

        p.reject_all_asymmetric_algos();
        for except in except.iter() {
            p.accept_asymmetric_algo(except.clone());
        }

        p
    }

    #[test]
    fn signature() {
        let t = SystemTime::now();

        for (asymm, algo, profile) in [
            (AsymmetricAlgorithm::RSA1024,
             PublicKeyAlgorithmSpecification::rsa(1024),
             Profile::RFC4880),
            (AsymmetricAlgorithm::RSA2048,
             PublicKeyAlgorithmSpecification::rsa(2048),
             Profile::RFC4880),
            (AsymmetricAlgorithm::EdDSA,
             PublicKeyAlgorithmSpecification::legacy_ed25519(),
             Profile::RFC4880),
            (AsymmetricAlgorithm::Ed25519,
             PublicKeyAlgorithmSpecification::ed25519(),
             Profile::RFC4880),
            (AsymmetricAlgorithm::Ed448,
             PublicKeyAlgorithmSpecification::ed448(),
             Profile::RFC4880),
            (AsymmetricAlgorithm::NistP256,
             PublicKeyAlgorithmSpecification::nistp256_for_signing(),
             Profile::RFC4880),
            (AsymmetricAlgorithm::NistP384,
             PublicKeyAlgorithmSpecification::nistp384_for_signing(),
             Profile::RFC4880),
            (AsymmetricAlgorithm::NistP521,
             PublicKeyAlgorithmSpecification::nistp521_for_signing(),
             Profile::RFC4880),
            (AsymmetricAlgorithm::BrainpoolP256,
             PublicKeyAlgorithmSpecification::brainpoolp256_for_signing(),
             Profile::RFC4880),
            (AsymmetricAlgorithm::BrainpoolP384,
             PublicKeyAlgorithmSpecification::brainpoolp384_for_signing(),
             Profile::RFC4880),
            (AsymmetricAlgorithm::BrainpoolP512,
             PublicKeyAlgorithmSpecification::brainpoolp512_for_signing(),
             Profile::RFC4880),
            (AsymmetricAlgorithm::MLDSA65_Ed25519,
             PublicKeyAlgorithmSpecification::mldsa65_ed25519(),
             Profile::RFC9580),
            (AsymmetricAlgorithm::MLDSA87_Ed448,
             PublicKeyAlgorithmSpecification::mldsa87_ed448(),
             Profile::RFC9580),
            // Skip: slow.
            //(AsymmetricAlgorithm::SLHDSA128s,
            // PublicKeyAlgorithmSpecification::slhdsa128s(),
            // Profile::RFC9580),
            (AsymmetricAlgorithm::SLHDSA128f,
             PublicKeyAlgorithmSpecification::slhdsa128f(),
             Profile::RFC9580),
            // Skip: slow.
            //(AsymmetricAlgorithm::SLHDSA256s,
            // PublicKeyAlgorithmSpecification::slhdsa256s(),
            // Profile::RFC9580),
        ] {
            eprintln!("Considering: {:?}", algo);

            if ! algo.is_supported() {
                eprintln!("  Algorithm not supported, skipping.");
                continue;
            }

            // Create a certificate with just the primary key whose
            // algorithm is the specified algorithm.
            let (cert, _rev) = CertBuilder::new()
                .set_signing_algorithm(algo)
                .set_profile(profile).expect("valid profile")
                .set_primary_key_flags(KeyFlags::signing())
                .generate()
                .expect("can generate certificate");
            assert_eq!(cert.keys().count(), 1);

            for (accept, algos) in &[
                (true, &[asymm][..]),
                (false, &[]),
            ] {
                eprintln!("  Configuring policy to {} algorithm",
                          if *accept {
                              "accept"
                          } else {
                              "reject"
                          });

                // Only accept the key's algorithm or nothing.
                let p = reject_all_except(algos);

                // Run this a few times, as signature size can vary.
                for i in 0..16 {
                    let signer = cert.primary_key()
                        .key()
                        .clone()
                        .parts_into_secret().expect("have secret key material")
                        .into_keypair().expect("have secret key material");
                    let mut sink = vec![];
                    let message = Message::new(&mut sink);
                    let mut signer = Signer::new(message, signer)
                        .expect("can initialize a streaming signer")
                        .detached()
                        .build()
                        .expect("can create streaming signer");
                    signer.write_all(b"yes!").expect("can write to signer");
                    signer.finalize().expect("can finalize signer");

                    let packet: Packet = Packet::from_reader(std::io::Cursor::new(sink))
                        .expect("Can parse a signature packet");

                    let Packet::Signature(sig) = packet else {
                        panic!("Should have a signature packet");
                    };

                    let std_policy = cert.with_policy(&p, t.clone());
                    let sig_policy = policy_check_signature(&p, t, &sig);
                    match (std_policy, sig_policy) {
                        (Ok(_), Ok(_)) => {
                            if i == 0 {
                                eprintln!("  Policy says cert and sig are valid");
                            }

                            assert!(accept);
                        }
                        (Err(c_err), Err(s_err)) => {
                            if i == 0 {
                                eprintln!("  Policy says cert and sig are both invalid:\
                                           \n    cert: {}\n     sig: {}",
                                          c_err, s_err);
                            }

                            assert!(! accept);
                        }
                        (Ok(_), Err(err)) => {
                            panic!("  Policy says cert is ok, but sig is invalid: {}",
                                   err);
                        }
                        (Err(err), Ok(())) => {
                            panic!("  Policy says sig is ok, but cert is invalid: {}",
                                   err);
                        }
                    }
                }
            }
        }
    }
}
