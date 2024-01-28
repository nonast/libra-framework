#![allow(unused)]
use std::{path::PathBuf, time::Duration};
use std::process::abort;

use anyhow::bail;
use clap::Parser;
use diem_config::config::NodeConfig;
// use diem_forge::LocalNode;
use diem_temppath::TempPath;
use diem_types::transaction::{Script, TransactionPayload};
use diem_types::validator_config::ValidatorOperatorConfigResource;
use futures_util::TryFutureExt;
use move_core_types::account_address::AccountAddress;

use libra_smoke_tests::libra_smoke::LibraSmoke;
use libra_txs::txs_cli_vals::ValidatorTxs;
use crate::rescue_tx::RescueTxOpts;
use std::fs;
use diem_config::keys::ConfigKey;
use diem_crypto::ed25519::PrivateKey;
use diem_forge::{LocalNode, LocalVersion, Node, NodeExt, Version};
use std::mem::ManuallyDrop;
use std::path::Path;
// use diem_types::chain_id::NamedChain;

use libra_wallet::validator_files::SetValidatorConfiguration;
use diem_genesis::config::{HostAndPort};
use diem_types::on_chain_config::new_epoch_event_key;
use diem_vm::move_vm_ext::SessionExt;
use libra_config::validator_config;
use libra_types::{exports::NamedChain};
use libra_wallet::core::legacy_scheme::LegacyKeyScheme;
use diem_crypto::bls12381::ProofOfPossession;
use move_core_types::value::MoveValue;
use diem_crypto::{bls12381};
use diem_genesis::keys::{PrivateIdentity, PublicIdentity};
use serde::Deserialize;
use libra_query::query_view;
use hex;
use hex::FromHex;

use crate::session_tools::{libra_run_session, libra_execute_session_function, writeset_voodoo_events};

// use ol_keys::scheme::KeyScheme;

#[derive(Parser)]

/// set up a twin of the network, with a synced db
/// and replace the validator with local Swarm validators
pub struct TwinOpts {
    // path of snapshot db we want marlon to drive
    #[clap(value_parser)]
    pub db_dir: PathBuf,
    /// The operator.yaml file which contains registration information
    #[clap(value_parser)]
    pub oper_file: Option<PathBuf>,
}

impl TwinOpts {
    /// takes a snapshot db and makes a validator set of ONE from an
    /// existing or NEW marlon rando account
    pub fn run(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// we need a new account config created locally
    /// Note, we do not use this function because it drops the swarm (and the temp. directory)
    /// after function call.
    pub async fn initialize_marlon_the_val() -> anyhow::Result<PathBuf> {
        // we use LibraSwarm to create a new folder with validator configs.
        // we then take the operator.yaml, and use it to register on a dirty db

        let mut s = LibraSmoke::new(Some(1)).await?;
        s.swarm.wait_all_alive(Duration::from_secs(10)).await?;
        let marlon = s.swarm.validators_mut().next().unwrap();
        println!("marlon peer id from init: {:?}", marlon.peer_id());

        // todo: operate.yaml is not created. We need to create it.
        // We could possible manually create this file.

        // let operator_account_address = marlon.config().get_peer_id().unwrap();
        // let operator_account_public_key = marlon.config().get_test_config().operator_keypair.0;
        // let consensus_public_key = marlon.config().get_test_config().consensus_keypair.0;


        marlon.stop();

        let host_and_port = HostAndPort::local(marlon.port()).unwrap();

        println!("host_and_port: {:?}", host_and_port);

        let path = marlon.config_path().parent().unwrap().to_path_buf();
        let data_path = path.join("data");
        println!("data_path: {:?}", data_path);


        // This one requires an owner.yaml file first.
        // let val_config = SetValidatorConfiguration::new(
        //     Some(data_path),
        //     String::from("marlon"),
        //     host_and_port,
        //     None,
        // );
        //
        // let (oper, owner) = val_config.set_config_files().unwrap();
        //
        // println!("oper: {:?}", oper);
        // println!("owner: {:?}", owner);





        // We need to get a mnemonic to create the owner.yaml and operator.yaml file.
        // We're just using a random mnemonic here to check if operator.yaml is created and
        // advance with the rest of the functions.
        let eve_keys = "recall october regret kite undo choice outside season business wall quit arrest vacant arrow giggle vote ghost winter hawk soft cheap decide exhaust spare".to_string();


        let public_identity = validator_config::initialize_validator(
            Some(data_path.clone()),
            Some(marlon.name()),
            host_and_port,
            Some(eve_keys),
            false,
            Some(NamedChain::MAINNET),
        )?;

        println!("public_identity: {:?}", public_identity);

        // helper to print contents
        TwinOpts::print_directory(&marlon.config_path().parent().unwrap().to_path_buf());

        Ok(marlon.config_path().parent().unwrap().join("data").join("operator.yaml"))
    }

    /// Initialize marlon and prevent the Drop trait. Create a persistent swarm directory.
    /// Must be manually dropped to prevent memory leaks!
    pub async fn initialize_marlon_the_val_and_prevent_drop() -> anyhow::Result<ManuallyDrop<LibraSmoke>> {
        let mut s = LibraSmoke::new(Some(1)).await?;
        s.swarm.wait_all_alive(Duration::from_secs(10)).await?;
        let marlon = s.swarm.validators_mut().next().unwrap();
        println!("marlon peer id from init: {:?}", marlon.peer_id());

        // Do not stop marlon, we need to query it.
        // marlon.stop();

        // // GENERATE OPERATOR.YAML
        // let host_and_port = HostAndPort::local(marlon.port()).unwrap();
        //
        // println!("host_and_port: {:?}", host_and_port);
        //
        // let path = marlon.config_path().parent().unwrap().to_path_buf();
        // let data_path = path.join("data");
        //
        // let eve_keys = "recall october regret kite undo choice outside season business wall quit arrest vacant arrow giggle vote ghost winter hawk soft cheap decide exhaust spare".to_string();
        //
        // // Here we use a different method to generate operator.yaml, which is basically what the
        // // previous one does but without all of the steps.
        // let (.., pub_id, keys) =
        //     libra_wallet::keys::refresh_validator_files(Some(eve_keys),Some(data_path.clone()), false)?;
        //
        // let host_and_port_node = HostAndPort::local(0).unwrap();
        //
        // let effective_username = marlon.name();
        // SetValidatorConfiguration::new(Some(data_path.clone()), effective_username.to_owned(), host_and_port.clone(), Some(host_and_port_node))
        //     .set_config_files()?;

        Ok(ManuallyDrop::new(s))
    }

    /// create the validator registration entry function payload
    /// needs the file operator.yaml
    pub fn register_marlon_tx(file: &PathBuf) -> anyhow::Result<TransactionPayload> {
        println!("operator path: {:?}", file.display());
        let tx = ValidatorTxs::Register {
            operator_file: Some(file.clone()),
        }
        .make_payload()?
        .encode();

        // todo: we need a script here instead of transaction payload!

        println!("tx: {:?}", tx);
        // if let diem_types::transaction::TransactionPayload::Script(s) = tx {
        //     return Ok(s);
        // }

        return Ok(tx);

        bail!("function did not return a script")
    }

    /// create the rescue blob which has one validator
    pub fn rescue_blob_with_one_val(brick_db: PathBuf, validator_address: AccountAddress) -> anyhow::Result<PathBuf> {
        // create the blob path
        let blob_path = diem_temppath::TempPath::new();
        blob_path.create_as_dir()?;

        let r = RescueTxOpts {
            data_path: brick_db.clone(),
            blob_path: Some(blob_path.path().to_owned()),
            script_path: None,
            framework_upgrade: true,
            debug_vals: Some(vec![validator_address]),
        };
        r.run()?;

        let file = blob_path.path().join("rescue.blob");
        Ok(file)
    }

    /// end to end with rando
    /// Which is basically running a new random swarm on an existing db.
    pub async fn apply_with_rando_e2e(brick_db: PathBuf) -> anyhow::Result<()> {
        // 1. create a new validator with a new account
        // let mut operator_file = TwinOpts::initialize_marlon_the_val().await?;
        let mut smoke = TwinOpts::initialize_marlon_the_val_and_prevent_drop().await?;
        // let operator_file = smoke.swarm.validators_mut().next().unwrap().config_path().parent().unwrap().join("data").join("operator.yaml");

        // get the necessary values from the current db
        let account = smoke.swarm.validators_mut().next().unwrap().config().get_peer_id().unwrap();

        // let private_identity_yaml = smoke.swarm.validators_mut().next().unwrap().config_path().parent().unwrap().join("private-identity.yaml");
        // let private_identity =
        //     serde_yaml::from_slice::<PrivateIdentity>(&fs::read(private_identity_yaml)?)?;
        // let consensus_private_key = private_identity.consensus_private_key;

        let public_identity_yaml = smoke.swarm.validators_mut().next().unwrap().config_path().parent().unwrap().join("public-identity.yaml");
        let public_identity =
            serde_yaml::from_slice::<PublicIdentity>(&fs::read(public_identity_yaml)?)?;
        let proof_of_possession = public_identity.consensus_proof_of_possession.unwrap().to_bytes().to_vec();
        let consensus_public_key_file = public_identity.consensus_public_key.clone().unwrap().to_string();

        // query the db for the values
        let query_res = query_view::get_view(
            &smoke.client(),
            "0x1::stake::get_validator_config",
            None,
            Some(account.to_string()),
        ).await.unwrap();

        // we don't need the node anymore
        // smoke.swarm.validators_mut().next().unwrap().stop();

        // println!("query_res: {:?}", query_res);
        // println!("query 3: {:?}", query_res[2].as_str().unwrap());

        // decode the hex string into a Vec<u8>

        let network_addresses = query_res[1].as_str().unwrap().strip_prefix("0x").unwrap();
        let fullnode_addresses = query_res[2].as_str().unwrap().strip_prefix("0x").unwrap();
        let consensus_public_key_chain = query_res[0].as_str().unwrap().strip_prefix("0x").unwrap();

        // let na = na[2..].as_bytes().to_vec();
        // let fa = fa[2..].as_bytes().to_vec();

        // let network_addresses = hex::FromHex::from_hex(na).unwrap();
        // let network_addresses = hex::decode(na[2..]).unwrap();
        // let fullnode_addresses = hex::decode(fa[2..]).unwrap();
        // let fullnode_addresses = hex::FromHex::from_hex(fa).unwrap();
        // let network_addresses = na;
        // let fullnode_addresses = fa;


        // for checking if both values are the same:
        let consensus_public_key_chain = hex::decode(consensus_public_key_chain).unwrap();
        let consensus_public_key_file = hex::decode(consensus_public_key_file).unwrap();
        let network_addresses = hex::decode(network_addresses).unwrap();
        let fullnode_addresses = hex::decode(fullnode_addresses).unwrap();
        // let consensus_public_key_file = hex::decode(consensus_public_key_file).unwrap();

        // println!("network_addresses: {:?}", network_addresses);
        // println!("fullnode_addresses: {:?}", fullnode_addresses);

        // let consensus_public_key_file: Vec<u8> = format!("0x{}",consensus_public_key_file.as_str()).split('x').collect();
        println!("consensus_public_key from CHAIN: {:?}", consensus_public_key_chain);
        println!("consensus_public_key from FILE: {:?}", consensus_public_key_file);

        assert_eq!(consensus_public_key_chain, consensus_public_key_file);
        println!("validator address: {:?}", account);

        // get the validator universe from swarm db so that we can check afterwards if there's a change.
        let query_res_1 = smoke.swarm.validators_mut().next().unwrap().rest_client().get_account_resource(AccountAddress::ONE, "0x1::validator_universe::ValidatorUniverse").await?;


        // 2. replace the swarm db with the brick db
        let swarm_db_path = smoke.swarm.validators_mut().next().unwrap().config().storage.dir();
        println!("Amount of validators: {:?}", smoke.swarm.validators_mut().count());
        println!("swarm_db: {:?}", swarm_db_path);
        // fs::remove_dir_all(&swarm_db_path)?;
        // note. clearing the storage also stops the node.
        smoke.swarm.validators_mut().next().unwrap().clear_storage();
        println!("removed the swarm db completely");
        println!("brick_db: {:?}", brick_db);
        println!("copying the brick db to the swarm db");
        // // this swaps the directories
        // fs::rename(brick_db, &swarm_db_path)?;
        // copy all the contents of the brick db to the swarm db
        TwinOpts::copy_contents(&brick_db, &swarm_db_path)?;
        println!("done copying the brick db to the swarm db");

        // 3. Create validator registration payload

        // let script = TwinOpts::register_marlon_tx(&operator_file)?;

        // 4. apply this script to the dirty db


        // todo: before running this, we need to first somehow allow this validator to register.
        // the error code that register_validator returns is this line https://github.com/nonast/libra-framework/blob/dc62b66099faa29023911a87dbb6cc4d52c840a3/framework/libra-framework/sources/modified_source/stake.move#L390
        // 1st option: configure the allowed validator list manually. "configure_allowed_validators"

        // test with existing slow wallet:
        // let account = AccountAddress::from_hex_literal("0x116c446a2d5bb191fa0ddb712d315059238bad6c6295ba88a199c2437f70e11b").unwrap();

        match libra_run_session(swarm_db_path.as_path(), |session| TwinOpts::combined_steps(session, account, consensus_public_key_file, proof_of_possession, network_addresses, fullnode_addresses), None) {
            Ok(_) => println!("Successfully got through this voodoo box"),
            Err(e) => {
                println!("err: {:?}", e);
                // we need to clean up the temp directory and running node.
                // Comment out if you want to keep the directory for debugging.
                unsafe {
                    ManuallyDrop::drop(&mut smoke);
                }
            },
        }


        // restart the validator
        smoke.swarm.validators_mut().next().unwrap().start();
        // print the contents of the directory
        // TwinOpts::print_directory(&swarm_db_path);
        smoke.swarm.wait_all_alive(Duration::from_secs(10)).await?;

        // compare query before and after db swap
        let query_res_2 = smoke.swarm.validators_mut().next().unwrap().rest_client().get_account_resource(AccountAddress::ONE, "0x1::validator_universe::ValidatorUniverse").await?;
        println!("query_res 1: {:?} \n query_res_2: {:?}", query_res_1, query_res_2);


        // then we can register the validator
        // libra_run_session(swarm_db_path.as_path(), |session| TwinOpts::register_validator(session, account, consensus_public_key_file, proof_of_possession, network_addresses, fullnode_addresses), None).unwrap();


        return Ok(());


        // get the address of marlon
        // println!("operator path: {:?}", operator_file.display());
        // let node_config_path = operator_file.parent().unwrap().parent().unwrap().join("node.yaml");
        // let validator_address = NodeConfig::load_from_path(&node_config_path)?.get_peer_id().unwrap();
        // println!("marlon address: {:?}", validator_address);
        //
        //
        // // 5. create a rescue blob with one validator
        // let blob = TwinOpts::rescue_blob_with_one_val(brick_db, validator_address)?;
        //
        // // apply the rescue blob to the new db
        // let r = RescueTxOpts {
        //     data_path: new_db.clone(),
        //     blob_path: Some(blob),
        //     script_path: None,
        //     framework_upgrade: false,
        //     debug_vals: Some(vec![validator_address]),
        // };
        // r.run()?;
        //
        // // apply the genesis tx
        //
        //
        //
        // // Manually drop the libra smoke swarm.
        // unsafe {
        //     ManuallyDrop::drop(&mut smoke);
        // }
        //
        // Ok(())
    }

    /// Function to call the register validator function
    fn register_validator(session: &mut SessionExt, account: AccountAddress, consensus_pubkey: Vec<u8>, proof_of_possession: Vec<u8>, network_addresses: Vec<u8>, fullnode_addresses: Vec<u8>) -> anyhow::Result<()> {
        // convert the arguments to MoveValues
        let signer = MoveValue::Signer(account);
        let consensus_pubkey = MoveValue::vector_u8(consensus_pubkey);
        let proof_of_possession = MoveValue::vector_u8(proof_of_possession);
        let network_addresses = MoveValue::vector_u8(network_addresses);
        let fullnode_addresses = MoveValue::vector_u8(fullnode_addresses);

        let args = vec![&signer, &consensus_pubkey, &proof_of_possession, &network_addresses, &fullnode_addresses];

        libra_execute_session_function(session, "0x1::validator_universe::register_validator", args)?;

        // to end this, we (might) need to do voodoo
        writeset_voodoo_events(session)?;

        Ok(())
    }

    /// Function to call the configure allowed validators function
    fn configure_validator(session: &mut SessionExt, validator: AccountAddress) -> anyhow::Result<()> {
        // account address of the diem_framework
        let signer = MoveValue::Signer(AccountAddress::ONE);
        let vector_val = MoveValue::vector_address(vec![validator]);

        let args = vec![&signer, &vector_val];

        libra_execute_session_function(session, "0x1::stake::configure_allowed_validators", args)?;

        // to end this, we (might) need to do voodoo
        writeset_voodoo_events(session)?;

        Ok(())
    }

    /// Function for combined function calls
    fn combined_steps(session: &mut SessionExt, validator: AccountAddress, consensus_pubkey: Vec<u8>, proof_of_possession: Vec<u8>, network_addresses: Vec<u8>, fullnode_addresses: Vec<u8>) -> anyhow::Result<()> {
        // account address of the diem_framework
        let signer = MoveValue::Signer(AccountAddress::ONE);
        let vector_val = MoveValue::vector_address(vec![validator]);

        let args = vec![&signer, &vector_val];

        libra_execute_session_function(session, "0x1::stake::configure_allowed_validators", args)?;

        let signer = MoveValue::Signer(validator);
        let signer_address = MoveValue::Address(validator);

        // // lets try to first create this account on chain.. (donor is random existing account)
        // let donor = AccountAddress::from_hex_literal("0x116c446a2d5bb191fa0ddb712d315059238bad6c6295ba88a199c2437f70e11b")?;
        // let donor_signer = MoveValue::Signer(donor);
        // let amount = MoveValue::U64(1000);
        // let args = vec![&signer_address];
        // libra_execute_session_function(session, "0x1::account::create_account", args)?;

        // // or try to create account like this..
        // let signer_one = MoveValue::Signer(AccountAddress::ONE);
        // let args = vec![&signer_one, &signer_address];
        // libra_execute_session_function(session, "0x1::ol_account::create_account", args)?;

        // // try to add validator
        // let args = vec![&signer];
        // libra_execute_session_function(session, "0x1::validator_universe::add", args)?;

        let consensus_pubkey = MoveValue::vector_u8(consensus_pubkey);
        let proof_of_possession = MoveValue::vector_u8(proof_of_possession);
        let network_addresses = MoveValue::vector_u8(network_addresses);
        let fullnode_addresses = MoveValue::vector_u8(fullnode_addresses);

        let args = vec![&signer, &consensus_pubkey, &proof_of_possession, &network_addresses, &fullnode_addresses];

        libra_execute_session_function(session, "0x1::validator_universe::register_validator", args)?;

        // to end this, we (might) need to do voodoo
        writeset_voodoo_events(session)?;

        Ok(())
    }

    /// Helper to print the contents of a directory
    fn print_directory(path: &PathBuf) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let abs_path = entry.path();

                    if let Some(abs_path_str) = abs_path.to_str() {
                        println!("Absolute Path: {}", abs_path_str);
                    } else {
                        println!("Failed to convert path to string.");
                    }
                }
            }
        } else {
            println!("Failed to read directory.");
        }
    }

    /// Copy contents from one directory to the other.
    fn copy_contents(source_dir: &PathBuf, destination_dir: &PathBuf) -> anyhow::Result<()> {
        // Create the destination directory if it doesn't exist
        fs::create_dir_all(destination_dir)?;

        // Iterate over the entries in the source directory
        for entry in fs::read_dir(source_dir)? {
            let entry = entry?;
            let source_path = entry.path();
            let file_name = entry.file_name();

            // Create the destination path by appending the file/directory name to the destination directory
            let destination_path = destination_dir.join(file_name);

            // Copy the entry to the destination path
            if entry.file_type()?.is_dir() {
                // If the entry is a directory, recursively copy its contents
                TwinOpts::copy_contents(&source_path, &destination_path)?;
            } else {
                // If the entry is a file, copy the file
                fs::copy(&source_path, &destination_path)?;
            }
        }

        Ok(())
    }
}
