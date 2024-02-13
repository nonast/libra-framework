#![allow(unused)]
use std::process::abort;
use std::time::Instant;
use std::{path::PathBuf, time::Duration};

use anyhow::bail;
use clap::Parser;
use diem_config::config::NodeConfig;
use diem_forge::Swarm;
use diem_forge::SwarmExt;
use diem_temppath::TempPath;
use diem_types::transaction::{Script, Transaction, TransactionPayload, WriteSetPayload};
use diem_types::validator_config::ValidatorOperatorConfigResource;
use fs_extra::dir;
use futures_util::TryFutureExt;
use move_core_types::account_address::AccountAddress;

use crate::diem_db_bootstrapper::BootstrapOpts;
use crate::{rescue_tx::RescueTxOpts, session_tools::ValCredentials};

use diem_config::keys::ConfigKey;
use diem_crypto::bls12381;
use diem_crypto::bls12381::ProofOfPossession;
use diem_crypto::ed25519::PrivateKey;
use diem_forge::{LocalNode, LocalVersion, Node, NodeExt, Version};
use diem_genesis::config::HostAndPort;
use diem_genesis::keys::{PrivateIdentity, PublicIdentity};
use diem_types::on_chain_config::new_epoch_event_key;
use diem_vm::move_vm_ext::SessionExt;
use hex;
use hex::FromHex;
use libra_config::validator_config;
use libra_query::query_view;
use libra_smoke_tests::libra_smoke::LibraSmoke;
use libra_txs::txs_cli_vals::ValidatorTxs;
use libra_types::exports::{Client, NamedChain};
use libra_wallet::core::legacy_scheme::LegacyKeyScheme;
use libra_wallet::validator_files::SetValidatorConfiguration;
use move_core_types::value::MoveValue;
use serde::Deserialize;
use std::fs;
use std::mem::ManuallyDrop;
use std::path::Path;

use crate::session_tools::{
    self, libra_execute_session_function, libra_run_session, session_add_validator,
    writeset_voodoo_events,
};

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
    /// provide info about the DB state, e.g. version
    #[clap(value_parser)]
    pub info: bool,
}

impl TwinOpts {
    /// takes a snapshot db and makes a validator set of ONE from an
    /// existing or NEW marlon rando account
    pub fn run(&self) -> anyhow::Result<()> {
        if self.info {
            return Ok(());
        }

        Ok(())
    }

    /// Initialize marlon and prevent the Drop trait. Create a persistent swarm directory.
    /// Must be manually dropped to prevent memory leaks!
    pub async fn initialize_marlon_the_val_and_prevent_drop(
    ) -> anyhow::Result<ManuallyDrop<LibraSmoke>> {
        let mut s = LibraSmoke::new(Some(1)).await?;
        s.swarm.wait_all_alive(Duration::from_secs(10)).await?;
        let marlon = s.swarm.validators_mut().next().unwrap();
        println!("marlon peer id from init: {:?}", marlon.peer_id());

        Ok(ManuallyDrop::new(s))
    }

    pub async fn make_rescue_twin_blob(
        db_path: &Path,
        cred: &ValCredentials,
    ) -> anyhow::Result<PathBuf> {
        println!("run session to create validator onboarding tx (rescue.blob)");
        let vmc = libra_run_session(
            db_path,
            |session| session_add_validator(session, cred),
            Some(vec![cred.account.clone()]),
        )?;
        let cs = session_tools::unpack_changeset(vmc)?;

        let gen_tx = Transaction::GenesisTransaction(WriteSetPayload::Direct(cs));
        let out = db_path.join("rescue.blob");

        let bytes = bcs::to_bytes(&gen_tx)?;
        std::fs::write(&out, bytes.as_slice())?;
        Ok(out)
    }

    pub async fn bootstrap_twin_db(
        swarm_db_path: &Path,
        genesis_blob_path: &Path,
    ) -> anyhow::Result<()> {
        println!("bootstrapping db with rescue.blob");

        let genesis_transaction = {
            let buf = fs::read(&genesis_blob_path).unwrap();
            bcs::from_bytes::<Transaction>(&buf).unwrap()
        };

        // replace with rescue cli
        let bootstrap = BootstrapOpts {
            db_dir: swarm_db_path.to_owned(),
            genesis_txn_file: genesis_blob_path.to_owned(),
            waypoint_to_verify: None,
            commit: false, // NOT APPLYING THE TX
            info: false,
        };

        let wp_opt = bootstrap.run()?;
        // replace with rescue cli
        let bootstrap = BootstrapOpts {
            db_dir: swarm_db_path.to_owned(),
            genesis_txn_file: genesis_blob_path.to_owned(),
            waypoint_to_verify: wp_opt,
            commit: true,
            info: false,
        };
        bootstrap.run()?;

        Ok(())
    }
    /// end to end with rando
    /// Which is basically running a new random swarm on an existing db.
    pub async fn apply_with_rando_e2e(prod_db: PathBuf) -> anyhow::Result<()> {
        // 1. create a new validator with a new account
        // let mut operator_file = TwinOpts::initialize_marlon_the_val().await?;
        let mut smoke = TwinOpts::initialize_marlon_the_val_and_prevent_drop().await?;

        let marlon_node = smoke.swarm.validators_mut().next().unwrap();

        let cred = Self::extract_credentials(marlon_node).await?;

        dbg!(&marlon_node.log_path());

        // 2. replace the swarm db with the brick db
        let swarm_db_path = marlon_node.config().storage.dir();

        // TODO: have we duplicated stopping the node?
        // note. clearing the storage also stops the node.
        marlon_node.clear_storage();

        Self::clone_db(&prod_db, &swarm_db_path)?;

        assert!(swarm_db_path.exists(), "no swarm path");

        // craft the rescue twin blob
        // we add the validator credentials
        // and add validator to set
        let genesis_blob_path = Self::make_rescue_twin_blob(&swarm_db_path, &cred).await?;
        assert!(genesis_blob_path.exists(), "no rescue blob created");

        // apply the rescue blob to the swarm db
        Self::bootstrap_twin_db(&swarm_db_path, &genesis_blob_path);

        // Ok now try to restart the swarm
        println!("restarting validator");
        smoke.swarm.validators_mut().for_each(|n| {
            dbg!(&n.log_path());
            n.start();
        });

        println!("wait for liveness");

        smoke
            .swarm
            .liveness_check(Instant::now().checked_add(Duration::from_secs(10)).unwrap());

        // std::thread::sleep(Duration::from_secs(30));

        // we need to clean up the temp directory and running node.
        // Comment out if you want to keep the directory for debugging.
        unsafe {
            ManuallyDrop::drop(&mut smoke);
        }

        return Ok(());
    }

    /// from an initialized swarm state, extract one node's credentials
    async fn extract_credentials(marlon_node: &LocalNode) -> anyhow::Result<ValCredentials> {
        println!("extracting swarm validator credentials");
        // get the necessary values from the current db
        let account = marlon_node.config().get_peer_id().unwrap();

        let public_identity_yaml = marlon_node
            .config_path()
            .parent()
            .unwrap()
            .join("public-identity.yaml");
        let public_identity =
            serde_yaml::from_slice::<PublicIdentity>(&fs::read(public_identity_yaml)?)?;
        let proof_of_possession = public_identity
            .consensus_proof_of_possession
            .unwrap()
            .to_bytes()
            .to_vec();
        let consensus_public_key_file = public_identity
            .consensus_public_key
            .clone()
            .unwrap()
            .to_string();

        // query the db for the values
        let query_res = query_view::get_view(
            &marlon_node.rest_client(),
            "0x1::stake::get_validator_config",
            None,
            Some(account.to_string()),
        )
        .await
        .unwrap();

        let network_addresses = query_res[1].as_str().unwrap().strip_prefix("0x").unwrap();
        let fullnode_addresses = query_res[2].as_str().unwrap().strip_prefix("0x").unwrap();
        let consensus_public_key_chain = query_res[0].as_str().unwrap().strip_prefix("0x").unwrap();

        // for checking if both values are the same:
        let consensus_public_key_chain = hex::decode(consensus_public_key_chain).unwrap();
        let consensus_pubkey = hex::decode(consensus_public_key_file).unwrap();
        let network_addresses = hex::decode(network_addresses).unwrap();
        let fullnode_addresses = hex::decode(fullnode_addresses).unwrap();

        assert_eq!(consensus_public_key_chain, consensus_pubkey);
        Ok(ValCredentials {
            account,
            consensus_pubkey,
            proof_of_possession,
            network_addresses,
            fullnode_addresses,
        })
    }

    fn clone_db(prod_db: &Path, swarm_db: &Path) -> anyhow::Result<()> {
        println!("copying the db db to the swarm db");
        println!("prod db path: {:?}", prod_db);
        println!("swarm db path: {:?}", swarm_db);

        // // this swaps the directories
        assert!(prod_db.exists());
        assert!(swarm_db.exists());
        let swarm_old_path = swarm_db.parent().unwrap().join("db-old");
        fs::create_dir(&swarm_old_path);
        let options = dir::CopyOptions::new(); //Initialize default values for CopyOptions

        // move source/dir1 to target/dir1
        dir::move_dir(&swarm_db, &swarm_old_path, &options)?;
        assert!(!swarm_db.exists());

        fs::create_dir(&swarm_db);
        dir::copy(&prod_db, &swarm_db.parent().unwrap(), &options)?;

        println!("db copied");
        Ok(())
    }

    /// Function for combined function calls
    fn session_add_validator(session: &mut SessionExt, cred: ValCredentials) -> anyhow::Result<()> {
        // account address of the diem_framework
        let signer = MoveValue::Signer(AccountAddress::ONE);
        let vector_val = MoveValue::vector_address(vec![cred.account]);

        let args = vec![&signer, &vector_val];

        libra_execute_session_function(session, "0x1::stake::configure_allowed_validators", args)?;

        let signer = MoveValue::Signer(cred.account);
        let signer_address = MoveValue::Address(cred.account);
        let consensus_pubkey = MoveValue::vector_u8(cred.consensus_pubkey);
        let proof_of_possession = MoveValue::vector_u8(cred.proof_of_possession);
        let network_addresses = MoveValue::vector_u8(cred.network_addresses);
        let fullnode_addresses = MoveValue::vector_u8(cred.fullnode_addresses);

        let args = vec![
            &signer,
            &consensus_pubkey,
            &proof_of_possession,
            &network_addresses,
            &fullnode_addresses,
        ];

        libra_execute_session_function(
            session,
            "0x1::validator_universe::register_validator",
            args,
        )?;

        // to end this, we (might) need to do voodoo
        writeset_voodoo_events(session)?;

        Ok(())
    }
}
