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
use std::io::Write;
use std::mem::ManuallyDrop;
use std::path::Path;
use dirs;
use diem_db_tool;
use diem_backup_cli::{
    coordinators::restore::{RestoreCoordinator, RestoreCoordinatorOpt},
    utils::GlobalRestoreOpt,
    storage::{DBToolStorageOpt, command_adapter::CommandAdapter},
};
use std::{sync::Arc};
use std::cell::RefCell;
use diem_backup_cli::metadata::cache::MetadataCacheOpt;
use diem_backup_cli::storage::command_adapter::CommandAdapterOpt;
use std::str::FromStr;
use git2::{Repository, Error, RemoteCallbacks, build::RepoBuilder};
use std::process::Command;

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
            None,
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

    // /// Function for combined function calls
    // fn session_add_validator(session: &mut SessionExt, cred: ValCredentials) -> anyhow::Result<()> {
    //     // account address of the diem_framework
    //     let signer = MoveValue::Signer(AccountAddress::ONE);
    //     let vector_val = MoveValue::vector_address(vec![cred.account]);

    //     let args = vec![&signer, &vector_val];

    //     libra_execute_session_function(session, "0x1::stake::configure_allowed_validators", args)?;

    //     let signer = MoveValue::Signer(cred.account);
    //     let signer_address = MoveValue::Address(cred.account);
    //     let consensus_pubkey = MoveValue::vector_u8(cred.consensus_pubkey);
    //     let proof_of_possession = MoveValue::vector_u8(cred.proof_of_possession);
    //     let network_addresses = MoveValue::vector_u8(cred.network_addresses);
    //     let fullnode_addresses = MoveValue::vector_u8(cred.fullnode_addresses);

    //     let args = vec![
    //         &signer,
    //         &consensus_pubkey,
    //         &proof_of_possession,
    //         &network_addresses,
    //         &fullnode_addresses,
    //     ];

    //     libra_execute_session_function(
    //         session,
    //         "0x1::validator_universe::register_validator",
    //         args,
    //     )?;

    //     // to end this, we (might) need to do voodoo
    //     writeset_voodoo_events(session)?;

    //     Ok(())
    // }


    /// Function to bootstrap a twin db from a snapshot
    /// bootstrap a prod database from a a github stored snapshot. Requires importing some libs
    /// from diem, but should just be reimplementing the Makefile sirouk provides.
    /// This currently only fetches the latest snapshot available on github.
    /// todo: create proper tool for restore
    /// The good ol' ol restore
    /// "
    /// When I couldn't fly
    /// Oh, you gave me wings
    /// You pick me up when I fall down
    /// You ring the bell before they count me out
    /// If I was drowning you would part the sea
    /// And risk your own life to rescue me
    /// "
    async fn restore_from_snapshot(
        swarm_db_path: &Path
    ) -> anyhow::Result<()> {
        const GITHUB_ORG: &str = "0LNetworkCommunity";
        const GITHUB_REPO: &str = "epoch-archive-mainnet";
        const GENESIS_DIRNAME: &str = "upgrades/v6.9.0";

        //   cd ~/epoch-archive-mainnet
        //   make restore-all

        /// 1. sync-repo
        // # if block added to allow developing on feature branch without the reset to main on every run
        // cd ${REPO_PATH} && git pull origin main && \
        // if [ `git rev-parse --abbrev-ref HEAD` = "main" ]; then \
        // git reset --hard origin/main && git clean -xdf; \
        // fi

        // We do not need to do this as we're cloning the repo


        /// 2. wipe-db
        // sudo rm -rf ${DB_PATH}
        // let home_path = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home dir"))?;
        let db_path = swarm_db_path;
        println!("Removing the db");
        fs::remove_dir_all(&db_path)?;

        /// 3. make restore-init
        // ${SOURCE_PATH}/target/release/libra config fullnode-init

        // we might not need to do this


        /// 4. make restore-genesis
        // mkdir -p ${GENESIS_PATH} &&
        // && cp -f ${REPO_PATH}/${GENESIS_DIRNAME}/waypoint.txt ${GENESIS_PATH}/waypoint.txt
        let parent_path = db_path.parent().ok_or_else(|| anyhow::anyhow!("no parent dir"))?;
        let genesis_path = parent_path.join("genesis");

        println!("Creating the genesis path");
        fs::create_dir(&genesis_path)?;

        // get the genesis waypoint from the repo and place it in our local genesis_path
        println!("Downloading the waypoint");
        let waypoint_path = genesis_path.join("waypoint.txt");
        TwinOpts::download_file_from_github(GITHUB_ORG, GITHUB_REPO, &format!("{}/waypoint.txt", GENESIS_DIRNAME), &waypoint_path).await?;

        // do the same for the genesis.blob
        println!("Downloading the genesis.blob");
        let genesis_blob_path = genesis_path.join("genesis.blob");
        TwinOpts::download_file_from_github(GITHUB_ORG, GITHUB_REPO, &format!("{}/genesis.blob", GENESIS_DIRNAME), &genesis_blob_path).await?;

        /// 5. cd ${ARCHIVE_PATH} && ${BIN_PATH}/${BIN_FILE} restore bootstrap-db --target-db-dir ${DB_PATH} --metadata-cache-dir ${REPO_PATH}/metacache --command-adapter-config ${REPO_PATH}/epoch-archive.yaml
        // ARCHIVE_PATH=${REPO_PATH}/snapshots
        // we have to get some tools from `diem-db-tool` to do this

        // the arguments required
        let target_db_dir = db_path;

        // We use this as metacache dir for now
        println!("Creating the metacache dir");
        let metadata_cache_dir = parent_path.join("/tmp/epoch-archive-mainnet/metacache");
        // fs::create_dir(&metadata_cache_dir)?;

        // we can try using this..
        // let command_adapter_config = parent_path.join("epoch-archive.yaml");
        // TwinOpts::download_file_from_github(GITHUB_ORG, GITHUB_REPO, "epoch-archive.yaml", &command_adapter_config).await?;

        println!("Fetching the command adapter config");
        let command_adapter_config = PathBuf::from("/tmp/epoch-archive-mainnet/epoch-archive.yaml");

        // now do the `restore bootstrap-db` command
        // todo: cleanup this mess by not using all this cli opts stuff

        println!("Restore coordinator opt");
        let opt = RestoreCoordinatorOpt {
            metadata_cache_opt: MetadataCacheOpt::new(Some(metadata_cache_dir)),
            replay_all: false,
            ledger_history_start_version: None,
            skip_epoch_endings: false,
        };

        // GlobalRestoreOpt
        println!("Global restore opt");
        let global = GlobalRestoreOpt {
            dry_run: false,
            db_dir: Some(target_db_dir.to_path_buf()),
            target_version: None,
            trusted_waypoints: Default::default(),
            rocksdb_opt: Default::default(),
            concurrent_downloads: Default::default(),
            replay_concurrency_level: Default::default(),
        };

        // DBToolStorageOpt
        println!("DBToolStorageOpt");
        let command_adapt_opt = CommandAdapterOpt::from_str(command_adapter_config.to_str().unwrap()).unwrap();
        let storage = Arc::new(CommandAdapter::new_with_opt(command_adapt_opt).await?);

        RestoreCoordinator::new(
            opt, //restorecoordopt
            global.try_into()?, //globalopt
            storage, //storageopt
        ).run().await?;


        Ok(())
    }

    // /// Function to download the snapshot repo from github [FAST?]
    // async fn clone_snapshot_repo(org: &str, repo: &str, target: &Path) -> anyhow::Result<()> {
    //     let url = format!(
    //         "https://github.com/{}/{}.git",
    //         org, repo
    //     );
    //
    //     // Directory where the repository will be cloned
    //
    //     let dest_path = target; // Ensure canonical path
    //
    //     // Clone the repository using Git CLI
    //     let status = Command::new("git")
    //         .arg("clone")
    //         .arg("--progress")  // Show progress during cloning
    //         .arg(&url)
    //         .arg(&dest_path)
    //         .status()?;
    //
    //     if status.success() {
    //         println!("Repository cloned successfully to: {:?}", dest_path);
    //         Ok(())
    //     } else {
    //         Err(anyhow::anyhow!("Failed to clone repository"))
    //     }
    // }

    /// Function to download the snapshot repo from github [SLOW!]
    async fn clone_snapshot_repo(org: &str, repo: &str, target: &Path) -> anyhow::Result<()> {
        let url = format!(
            "https://github.com/{}/{}.git",
            org, repo
        );

        // Directory where the repository will be cloned
        let dest_path = Path::new(target);

        // Set up custom callbacks for progress reporting
        let mut callbacks = RemoteCallbacks::new();
        let last_progress = RefCell::new(0);

        callbacks.transfer_progress(move |progress| {
            let current_progress = progress.received_objects() * 100 / progress.total_objects();
            let last_progress_copy = *last_progress.borrow();
            // Print progress only when it makes significant progress (e.g., every 10%)
            if current_progress != last_progress_copy {
                println!("Cloning: {}% done", current_progress);
                *last_progress.borrow_mut() = current_progress;
            }
            true // Continue cloning
        });

        // Prepare fetch options.
          let mut fo = git2::FetchOptions::new();
          fo.remote_callbacks(callbacks);

          // Prepare builder.
          let mut builder = git2::build::RepoBuilder::new();
          builder.fetch_options(fo);

        builder.clone(&url, dest_path)?;

        Ok(())
    }

    /// Function to download a single file from github
    async fn download_file_from_github(
        org: &str,
        repo: &str,
        path: &str,
        target: &Path,
    ) -> anyhow::Result<()> {
        let url = format!(
            "https://raw.githubusercontent.com/{}/{}/main/{}",
            org, repo, path
        );
        let response = reqwest::get(&url).await?;
        let mut file = fs::File::create(&target)?;
        file.write_all(&response.bytes().await?)?;
        Ok(())
    }
}



#[tokio::test]
async fn test_twin_with_rando() -> anyhow::Result<()> {
    println!("Hi, I'm rando");

    // // for if you want to use your own production db
    let prod_db_to_clone = PathBuf::from("/root/db");

    TwinOpts::apply_with_rando_e2e(prod_db_to_clone).await?;
    Ok(())
}

#[tokio::test]
async fn test_restore_snapshot() -> anyhow::Result<()> {
    // let swarm_db_path = PathBuf::from("/root/db");
    // let mut smoke = TwinOpts::initialize_marlon_the_val_and_prevent_drop().await?;
    // let db_path = smoke.swarm.validators_mut().next().unwrap().config().storage.dir();

    let db_path = PathBuf::from("/private/var/folders/c7/zqx97b6d1bqcqbrw49chz9ph0000gn/T/.tmpmBvwnw/0/db");

    // we need to do this to reset the state for testing
    fs::create_dir(&db_path)?;
    let parent_path = db_path.parent().ok_or_else(|| anyhow::anyhow!("no parent dir"))?;
    let genesis_path = parent_path.join("genesis");
    fs::remove_dir_all(&genesis_path)?;

    println!("db path: {:?}", db_path);

    TwinOpts::restore_from_snapshot(&db_path).await?;
    Ok(())
}

#[tokio::test]
async fn test_repo_clone() -> anyhow::Result<()> {
    let org = "0LNetworkCommunity";
    let repo = "epoch-archive-mainnet";
    let target = PathBuf::from("/tmp/epoch-archive-mainnet");

    // clean previous clone
    fs::remove_dir_all(&target)?;

    TwinOpts::clone_snapshot_repo(org, repo, &target).await?;
    Ok(())
}
