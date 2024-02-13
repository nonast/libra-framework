mod support;
use std::path::PathBuf;
use rescue::twin::TwinOpts;


#[tokio::test]
async fn test_twin_with_rando() -> anyhow::Result<()> {
    println!("Hi, I'm rando");

    // // for if you want to use your own production db
    let prod_db_to_clone = PathBuf::from("/root/db");

    TwinOpts::apply_with_rando_e2e(prod_db_to_clone).await?;

    // // get the validator universe from swarm db so that we can check afterwards if there's a change.
    // let query_res_1 = marlon_node
    //     .rest_client()
    //     .get_account_resource(
    //         AccountAddress::ONE,
    //         "0x1::validator_universe::ValidatorUniverse",
    //     )
    //     .await?;

    Ok(())
}
