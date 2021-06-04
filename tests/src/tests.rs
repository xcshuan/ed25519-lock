use super::*;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

use rand::{rngs::OsRng, thread_rng, Rng};

const MAX_CYCLES: u64 = 1000_000_000;

// error numbers
const ERROR_EMPTY_ARGS: i8 = 5;

use super::mol::*;
use ed25519_dalek::*;
#[test]
fn test_success() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("eddsa-lock");
    let out_point = context.deploy_cell(contract_bin);

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, Bytes::from(vec![42]))
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let mut csrng = OsRng {};
    let mut sigs_builder = SignatureVecBuilder::default();

    let mut t = thread_rng();
    for _ in 0..30 {
        let mut mes = vec![0u8; 32];
        t.fill(&mut mes[..]);

        let kp = Keypair::generate(&mut csrng);
        let pk = kp.public;
        let sig = kp.sign(&mes);

        sigs_builder = sigs_builder.push(
            SignatureBuilder::default()
                .mes(Bytes::from(mes).pack())
                .sig(Bytes::from(sig.to_bytes().to_vec()).pack())
                .pubkey(Bytes::from(pk.to_bytes().to_vec()).pack())
                .build(),
        );
    }

    let sigs = sigs_builder.build();

    println!("sigs len:{}", sigs.as_slice().len());

    let witness = WitnessArgsBuilder::default()
        .lock(Some(sigs.as_bytes()).pack())
        .build();

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .witness(witness.as_bytes().pack())
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}
