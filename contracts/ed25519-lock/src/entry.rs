// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{
        bytes::Bytes,
        prelude::{Entity, Unpack},
    },
    debug,
    high_level::{load_script, load_tx_hash, load_witness_args},
};

use ed25519::signature::Signature;
use ed25519_dalek::*;
use mol::SignatureVec;

use crate::error::Error;

pub fn main() -> Result<(), Error> {
    // remove below examples and write your code here
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    debug!("script args is {:?}", args);

    let tx_hash = load_tx_hash()?;
    debug!("tx hash is {:?}", tx_hash);

    let witness = load_witness_args(0, Source::Input).unwrap();

    let witness_byte = witness.lock();

    if let Some(witness) = witness_byte.to_opt() {
        let w: Vec<u8> = witness.unpack();
        let sig_vec = SignatureVec::from_compatible_slice(&w).unwrap();

        let mut mess = vec![];
        let mut sigs = vec![];
        let mut pubs = vec![];

        for i in sig_vec.into_iter() {
            let sig: Vec<u8> = i.sig().unpack();
            let sig = Signature::from_bytes(&sig).unwrap();
            let pk: Vec<u8> = i.pubkey().unpack();
            let pk = PublicKey::from_bytes(&pk).unwrap();

            let mes: Vec<u8> = i.mes().unpack();
            mess.push(mes);

            sigs.push(sig);
            pubs.push(pk);
        }

        let mess: Vec<&[u8]> = mess.iter().map(|v| &v[..]).collect();
        verify_batch(&mess[..], &sigs, &pubs).unwrap();
    }

    Ok(())
}
