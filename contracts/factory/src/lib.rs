//! SplitFactory — clone-factory for per-invoice split contract instances.
//!
//! Deploying a fresh WASM instance per invoice is gas-intensive. This factory
//! deploys minimal-proxy clones pointing to a single canonical WASM blob,
//! reducing deployment cost while maintaining per-invoice state isolation.

#![no_std]

use soroban_sdk::{contract, contractimpl, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env, Symbol, Val, Vec};

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

fn factory_admin_key() -> Symbol {
    symbol_short!("fct_adm")
}

/// Approved WASM hashes allowlist key — instance storage.
/// Maps to a `Vec<BytesN<32>>` containing all approved WASM hashes.
fn approved_wasm_hashes_key() -> Symbol {
    symbol_short!("appr_wh")
}

/// Per-creator deployed contracts list — persistent storage.
fn deployed_contracts_key(creator: &Address) -> (Symbol, Address) {
    (symbol_short!("deployed"), creator.clone())
}

/// Per-(creator, salt) deployed address — used to detect duplicate salts.
fn salt_key(creator: &Address, salt: &BytesN<32>) -> (Symbol, Address, BytesN<32>) {
    (symbol_short!("salt"), creator.clone(), salt.clone())
}

/// Maximum number of deployed contracts per creator (DoS bound).
const MAX_DEPLOYMENTS_PER_CREATOR: u32 = 10_000;

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Emitted when a new split contract is deployed by the factory.
///
/// Topics: `(factory, deployed, creator)`
/// Data: `contract_address`
///
/// # Parameters
/// * `env`              — The current Soroban execution environment.
/// * `creator`          — The address that triggered the deployment.
/// * `contract_address` — The address of the newly deployed contract.
pub fn contract_deployed(env: &Env, creator: &Address, contract_address: &Address) {
    env.events().publish(
        (
            symbol_short!("factory"),
            symbol_short!("deployed"),
            creator.clone(),
        ),
        contract_address.clone(),
    );
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct SplitFactory;

#[contractimpl]
impl SplitFactory {
    /// Initialise the factory by recording its admin.
    ///
    /// Must be called exactly once after the contract is deployed. Subsequent
    /// calls panic with `"already initialized"`.
    ///
    /// # Parameters
    /// * `env`   — The current Soroban execution environment.
    /// * `admin` — The address that will become the factory administrator.
    ///
    /// # Panics
    /// Panics with `"already initialized"` if the factory has already been
    /// initialised.
    pub fn initialize(env: Env, admin: Address) {
        assert!(
            !env.storage().instance().has(&factory_admin_key()),
            "already initialized"
        );
        env.storage().instance().set(&factory_admin_key(), &admin);
    }

    /// Add a WASM hash to the approved deployment allowlist.
    ///
    /// Only the factory admin may call this. Subsequent calls to
    /// [`Self::deploy_invoice_contract`] will only succeed when the supplied
    /// `wasm_hash` appears in the allowlist.
    ///
    /// # Parameters
    /// * `env`       — The current Soroban execution environment.
    /// * `admin`     — The factory administrator address; requires auth.
    /// * `wasm_hash` — The 32-byte SHA-256 hash of the WASM blob to approve.
    ///
    /// # Panics
    /// Panics if `admin` is not the factory administrator.
    pub fn approve_wasm_hash(env: Env, admin: Address, wasm_hash: BytesN<32>) {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&factory_admin_key())
            .expect("factory not initialized");
        assert!(stored_admin == admin, "not factory admin");
        admin.require_auth();

        let mut hashes: Vec<BytesN<32>> = env
            .storage()
            .instance()
            .get(&approved_wasm_hashes_key())
            .unwrap_or_else(|| Vec::new(&env));

        // Avoid duplicates.
        if !hashes.contains(&wasm_hash) {
            hashes.push_back(wasm_hash);
            env.storage()
                .instance()
                .set(&approved_wasm_hashes_key(), &hashes);
        }
    }

    /// Remove a WASM hash from the approved deployment allowlist.
    ///
    /// Only the factory admin may call this. After removal, subsequent
    /// deployment requests specifying the revoked hash will be rejected.
    ///
    /// # Parameters
    /// * `env`       — The current Soroban execution environment.
    /// * `admin`     — The factory administrator address; requires auth.
    /// * `wasm_hash` — The 32-byte SHA-256 hash to remove from the allowlist.
    ///
    /// # Panics
    /// Panics if `admin` is not the factory administrator.
    pub fn revoke_wasm_hash(env: Env, admin: Address, wasm_hash: BytesN<32>) {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&factory_admin_key())
            .expect("factory not initialized");
        assert!(stored_admin == admin, "not factory admin");
        admin.require_auth();

        let hashes: Vec<BytesN<32>> = env
            .storage()
            .instance()
            .get(&approved_wasm_hashes_key())
            .unwrap_or_else(|| Vec::new(&env));

        let mut new_hashes: Vec<BytesN<32>> = Vec::new(&env);
        for h in hashes.iter() {
            if h != wasm_hash {
                new_hashes.push_back(h.clone());
            }
        }
        env.storage()
            .instance()
            .set(&approved_wasm_hashes_key(), &new_hashes);
    }

    /// Return whether a specific WASM hash is in the approved allowlist.
    ///
    /// # Parameters
    /// * `env`       — The current Soroban execution environment.
    /// * `wasm_hash` — The 32-byte SHA-256 hash to query.
    pub fn is_wasm_hash_approved(env: Env, wasm_hash: BytesN<32>) -> bool {
        let hashes: Vec<BytesN<32>> = env
            .storage()
            .instance()
            .get(&approved_wasm_hashes_key())
            .unwrap_or_else(|| Vec::new(&env));
        hashes.contains(&wasm_hash)
    }

    /// Deploy a new split contract instance using the clone-factory pattern.
    ///
    /// Uses `env.deployer().with_current_contract(salt)` so that the deployed
    /// address is deterministic for a given `(creator, salt)` pair. Duplicate
    /// salts for the same creator are rejected.
    ///
    /// # Parameters
    /// * `creator`     — The creator address; requires auth.
    /// * `wasm_hash`   — SHA-256 hash of the pre-uploaded split-contract WASM.
    ///                   Must be present in the admin-managed approved allowlist.
    /// * `salt`        — 32-byte uniqueness salt; determines the deployed address.
    /// * `init_args`   — Constructor arguments forwarded to the deployed contract.
    ///
    /// # Returns
    /// The `Address` of the newly deployed contract.
    ///
    /// # Panics
    /// Panics with `"wasm hash not approved"` if `wasm_hash` is not in the allowlist.
    pub fn deploy_invoice_contract(
        env: Env,
        creator: Address,
        wasm_hash: BytesN<32>,
        salt: BytesN<32>,
        init_args: soroban_sdk::Vec<Val>,
    ) -> Address {
        creator.require_auth();

        // Reject any WASM hash that has not been explicitly approved by the admin.
        let approved_hashes: Vec<BytesN<32>> = env
            .storage()
            .instance()
            .get(&approved_wasm_hashes_key())
            .unwrap_or_else(|| Vec::new(&env));
        assert!(
            approved_hashes.contains(&wasm_hash),
            "wasm hash not approved"
        );

        // Reject duplicate salts for the same creator.
        let salt_storage_key = salt_key(&creator, &salt);
        assert!(
            !env.storage().persistent().has(&salt_storage_key),
            "duplicate salt for creator"
        );

        // Enforce per-creator deployment cap (DoS bound).
        let deployments_key = deployed_contracts_key(&creator);
        let deployments: Vec<Address> = env
            .storage()
            .persistent()
            .get(&deployments_key)
            .unwrap_or_else(|| Vec::new(&env));
        assert!(
            deployments.len() < MAX_DEPLOYMENTS_PER_CREATOR as u32,
            "deployment limit exceeded"
        );

        // Derive a per-(creator, salt) effective deployment salt so different
        // creators can independently reuse the same user-provided salt without
        // address collisions. effective_salt = sha256(creator_xdr || user_salt).
        let mut salt_input = creator.clone().to_xdr(&env);
        salt_input.append(&Bytes::from_array(&env, &salt.to_array()));
        let effective_salt: BytesN<32> = env.crypto().sha256(&salt_input).into();

        // Deploy using the clone-factory pattern.
        let deployed_address = env
            .deployer()
            .with_current_contract(effective_salt)
            .deploy(wasm_hash);

        // Invoke init on the deployed contract if init_args is non-empty.
        //
        // Safety / atomicity (#49): `env.invoke_contract` propagates any panic
        // from the callee back to this call frame, causing the entire
        // transaction to revert. Deployment-state mutations below are therefore
        // only reachable when initialization succeeds, guaranteeing that no
        // uninitialized contract is ever recorded in the deployment tracking.
        //
        // Callers MUST supply the exact argument list expected by the deployed
        // contract's `initialize` function. A mismatched signature will cause
        // the sub-call to panic and atomically roll back the deployment.
        if !init_args.is_empty() {
            env.invoke_contract::<Val>(
                &deployed_address,
                &Symbol::new(&env, "initialize"),
                init_args,
            );
        }

        // Deployment state is only committed here — after initialization has
        // completed successfully (#49). If the invoke_contract call above
        // panicked, execution never reaches this point.

        // Record the deployed address.
        let mut updated_deployments = deployments;
        updated_deployments.push_back(deployed_address.clone());
        env.storage()
            .persistent()
            .set(&deployments_key, &updated_deployments);

        // Mark the salt as used.
        env.storage()
            .persistent()
            .set(&salt_storage_key, &deployed_address);

        // Emit event.
        contract_deployed(&env, &creator, &deployed_address);

        deployed_address
    }

    /// Return all deployed contract addresses for a given creator.
    ///
    /// Looks up the persistent list of contracts that `creator` has deployed
    /// through this factory. Returns an empty `Vec` when the creator has not
    /// yet deployed any contracts.
    ///
    /// # Parameters
    /// * `env`     — The current Soroban execution environment.
    /// * `creator` — The creator address to query.
    ///
    /// # Returns
    /// A `Vec<Address>` of contract addresses in deployment order. Empty if
    /// no contracts have been deployed for this creator.
    pub fn get_deployments(env: Env, creator: Address) -> Vec<Address> {
        env.storage()
            .persistent()
            .get(&deployed_contracts_key(&creator))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Check whether a specific (creator, salt) pair has already been used.
    ///
    /// Because the deployed address is deterministic per `(creator, salt)`,
    /// the factory rejects duplicate salts for the same creator. Use this
    /// view function before calling [`Self::deploy_invoice_contract`] to
    /// pre-check whether a salt is available.
    ///
    /// # Parameters
    /// * `env`     — The current Soroban execution environment.
    /// * `creator` — The creator address to check.
    /// * `salt`    — The 32-byte salt to check.
    ///
    /// # Returns
    /// `true` if the `(creator, salt)` pair was already used in a previous
    /// deployment; `false` otherwise.
    pub fn is_salt_used(env: Env, creator: Address, salt: BytesN<32>) -> bool {
        env.storage().persistent().has(&salt_key(&creator, &salt))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Events as _}, BytesN, Env, TryFromVal, Val, Vec};

    /// Minimal valid Soroban WASM stub (soroban-sdk doctest fixture).
    const STUB_WASM: &[u8] = include_bytes!("../../../tests/fixtures/stub_contract.wasm");

    #[test]
    fn test_deploy_single_contract() {
        let env = Env::default();
        env.mock_all_auths();

        let factory_admin = Address::generate(&env);
        let factory_id = env.register(SplitFactory, ());
        let factory_client = SplitFactoryClient::new(&env, &factory_id);
        factory_client.initialize(&factory_admin);

        let wasm_hash = env.deployer().upload_contract_wasm(STUB_WASM);
        // Approve the WASM hash before deployment.
        factory_client.approve_wasm_hash(&factory_admin, &wasm_hash);

        let creator = Address::generate(&env);
        let salt = BytesN::from_array(&env, &[1u8; 32]);
        let init_args = Vec::<Val>::new(&env);

        let addr = factory_client.deploy_invoice_contract(
            &creator,
            &wasm_hash,
            &salt,
            &init_args,
        );

        let deployments = factory_client.get_deployments(&creator);
        assert_eq!(deployments.len(), 1);
        assert_eq!(deployments.get_unchecked(0), addr);
    }

    #[test]
    fn test_deploy_two_contracts_unique_addresses() {
        let env = Env::default();
        env.mock_all_auths();

        let factory_admin = Address::generate(&env);
        let factory_id = env.register(SplitFactory, ());
        let factory_client = SplitFactoryClient::new(&env, &factory_id);
        factory_client.initialize(&factory_admin);

        let wasm_hash = env.deployer().upload_contract_wasm(STUB_WASM);
        // Approve the WASM hash before deployment.
        factory_client.approve_wasm_hash(&factory_admin, &wasm_hash);

        let creator = Address::generate(&env);
        let init_args = Vec::<Val>::new(&env);

        let salt1 = BytesN::from_array(&env, &[1u8; 32]);
        let addr1 = factory_client.deploy_invoice_contract(
            &creator,
            &wasm_hash,
            &salt1,
            &init_args,
        );

        let salt2 = BytesN::from_array(&env, &[2u8; 32]);
        let addr2 = factory_client.deploy_invoice_contract(
            &creator,
            &wasm_hash,
            &salt2,
            &init_args,
        );

        assert_ne!(addr1, addr2);

        let deployments = factory_client.get_deployments(&creator);
        assert_eq!(deployments.len(), 2);
        assert_eq!(deployments.get_unchecked(0), addr1);
        assert_eq!(deployments.get_unchecked(1), addr2);
    }

    #[test]
    #[should_panic(expected = "duplicate salt for creator")]
    fn test_duplicate_salt_rejected() {
        let env = Env::default();
        env.mock_all_auths();

        let factory_admin = Address::generate(&env);
        let factory_id = env.register(SplitFactory, ());
        let factory_client = SplitFactoryClient::new(&env, &factory_id);
        factory_client.initialize(&factory_admin);

        let wasm_hash = env.deployer().upload_contract_wasm(STUB_WASM);
        // Approve the WASM hash before deployment.
        factory_client.approve_wasm_hash(&factory_admin, &wasm_hash);

        let creator = Address::generate(&env);
        let salt = BytesN::from_array(&env, &[1u8; 32]);
        let init_args = Vec::<Val>::new(&env);

        factory_client.deploy_invoice_contract(&creator, &wasm_hash, &salt, &init_args);
        // Same salt, same creator — should panic.
        factory_client.deploy_invoice_contract(&creator, &wasm_hash, &salt, &init_args);
    }

    #[test]
    fn test_different_creators_same_salt_allowed() {
        let env = Env::default();
        env.mock_all_auths();

        let factory_admin = Address::generate(&env);
        let factory_id = env.register(SplitFactory, ());
        let factory_client = SplitFactoryClient::new(&env, &factory_id);
        factory_client.initialize(&factory_admin);

        let wasm_hash = env.deployer().upload_contract_wasm(STUB_WASM);
        // Approve the WASM hash before deployment.
        factory_client.approve_wasm_hash(&factory_admin, &wasm_hash);

        let init_args = Vec::<Val>::new(&env);
        let salt = BytesN::from_array(&env, &[1u8; 32]);

        let creator1 = Address::generate(&env);
        let addr1 = factory_client.deploy_invoice_contract(&creator1, &wasm_hash, &salt, &init_args);

        let creator2 = Address::generate(&env);
        let addr2 = factory_client.deploy_invoice_contract(&creator2, &wasm_hash, &salt, &init_args);

        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_contract_deployed_event_emitted() {
        let env = Env::default();
        env.mock_all_auths();

        let factory_admin = Address::generate(&env);
        let factory_id = env.register(SplitFactory, ());
        let factory_client = SplitFactoryClient::new(&env, &factory_id);
        factory_client.initialize(&factory_admin);

        let wasm_hash = env.deployer().upload_contract_wasm(STUB_WASM);
        // Approve the WASM hash before deployment.
        factory_client.approve_wasm_hash(&factory_admin, &wasm_hash);

        let creator = Address::generate(&env);
        let salt = BytesN::from_array(&env, &[1u8; 32]);
        let init_args = Vec::<Val>::new(&env);

        factory_client.deploy_invoice_contract(&creator, &wasm_hash, &salt, &init_args);

        // Verify the ContractDeployed event was emitted.
        let events = env.events().all();
        let mut found = false;
        for event in events.events().iter() {
            let soroban_sdk::xdr::ContractEventBody::V0(body) = &event.body;
            let mut topics = Vec::new(&env);
            let topics_ref: &[soroban_sdk::xdr::ScVal] = body.topics.as_ref();
            for v in topics_ref.iter() {
                if let Ok(val) = Val::try_from_val(&env, v) {
                    topics.push_back(val);
                }
            }
            // topics: (factory, deployed, creator)
            if topics.len() >= 3 {
                if let Ok(t0) = <Symbol as TryFromVal<Env, Val>>::try_from_val(&env, &topics.get_unchecked(0)) {
                    if t0 == symbol_short!("factory") {
                        found = true;
                        break;
                    }
                }
            }
        }
        assert!(found, "ContractDeployed event not emitted");
    }

    #[test]
    fn test_is_salt_used() {
        let env = Env::default();
        env.mock_all_auths();

        let factory_admin = Address::generate(&env);
        let factory_id = env.register(SplitFactory, ());
        let factory_client = SplitFactoryClient::new(&env, &factory_id);
        factory_client.initialize(&factory_admin);

        let wasm_hash = env.deployer().upload_contract_wasm(STUB_WASM);
        // Approve the WASM hash before deployment.
        factory_client.approve_wasm_hash(&factory_admin, &wasm_hash);

        let creator = Address::generate(&env);
        let salt = BytesN::from_array(&env, &[1u8; 32]);
        let init_args = Vec::<Val>::new(&env);

        assert!(!factory_client.is_salt_used(&creator, &salt));
        factory_client.deploy_invoice_contract(&creator, &wasm_hash, &salt, &init_args);
        assert!(factory_client.is_salt_used(&creator, &salt));
    }

    #[test]
    fn test_empty_get_deployments() {
        let env = Env::default();
        env.mock_all_auths();

        let factory_admin = Address::generate(&env);
        let factory_id = env.register(SplitFactory, ());
        let factory_client = SplitFactoryClient::new(&env, &factory_id);
        factory_client.initialize(&factory_admin);

        let creator = Address::generate(&env);
        assert_eq!(factory_client.get_deployments(&creator).len(), 0);
    }

    // -----------------------------------------------------------------------
    // Security tests — Issue #4: Unrestricted WASM Hash
    // -----------------------------------------------------------------------

    /// Deploying with an unapproved WASM hash must be rejected.
    #[test]
    #[should_panic(expected = "wasm hash not approved")]
    fn test_deploy_unapproved_wasm_hash_rejected() {
        let env = Env::default();
        env.mock_all_auths();

        let factory_admin = Address::generate(&env);
        let factory_id = env.register(SplitFactory, ());
        let factory_client = SplitFactoryClient::new(&env, &factory_id);
        factory_client.initialize(&factory_admin);

        // Upload but deliberately DO NOT approve the hash.
        let wasm_hash = env.deployer().upload_contract_wasm(STUB_WASM);

        let creator = Address::generate(&env);
        let salt = BytesN::from_array(&env, &[1u8; 32]);
        let init_args = Vec::<Val>::new(&env);

        // Should panic: "wasm hash not approved".
        factory_client.deploy_invoice_contract(&creator, &wasm_hash, &salt, &init_args);
    }

    /// A completely arbitrary (random) WASM hash must also be rejected.
    #[test]
    #[should_panic(expected = "wasm hash not approved")]
    fn test_deploy_arbitrary_wasm_hash_rejected() {
        let env = Env::default();
        env.mock_all_auths();

        let factory_admin = Address::generate(&env);
        let factory_id = env.register(SplitFactory, ());
        let factory_client = SplitFactoryClient::new(&env, &factory_id);
        factory_client.initialize(&factory_admin);

        // Approve a real WASM hash but try to deploy with a different one.
        let real_hash = env.deployer().upload_contract_wasm(STUB_WASM);
        factory_client.approve_wasm_hash(&factory_admin, &real_hash);

        // Forge a completely different hash.
        let forged_hash = BytesN::from_array(&env, &[0xdeu8; 32]);

        let creator = Address::generate(&env);
        let salt = BytesN::from_array(&env, &[1u8; 32]);
        let init_args = Vec::<Val>::new(&env);

        // Should panic: "wasm hash not approved".
        factory_client.deploy_invoice_contract(&creator, &forged_hash, &salt, &init_args);
    }

    /// After revoking an approved hash it must no longer be deployable.
    #[test]
    #[should_panic(expected = "wasm hash not approved")]
    fn test_revoked_wasm_hash_rejected() {
        let env = Env::default();
        env.mock_all_auths();

        let factory_admin = Address::generate(&env);
        let factory_id = env.register(SplitFactory, ());
        let factory_client = SplitFactoryClient::new(&env, &factory_id);
        factory_client.initialize(&factory_admin);

        let wasm_hash = env.deployer().upload_contract_wasm(STUB_WASM);
        factory_client.approve_wasm_hash(&factory_admin, &wasm_hash);
        // Revoke the hash immediately.
        factory_client.revoke_wasm_hash(&factory_admin, &wasm_hash);

        let creator = Address::generate(&env);
        let salt = BytesN::from_array(&env, &[1u8; 32]);
        let init_args = Vec::<Val>::new(&env);

        // Should panic: "wasm hash not approved".
        factory_client.deploy_invoice_contract(&creator, &wasm_hash, &salt, &init_args);
    }

    /// `is_wasm_hash_approved` reflects approve/revoke lifecycle correctly.
    #[test]
    fn test_is_wasm_hash_approved() {
        let env = Env::default();
        env.mock_all_auths();

        let factory_admin = Address::generate(&env);
        let factory_id = env.register(SplitFactory, ());
        let factory_client = SplitFactoryClient::new(&env, &factory_id);
        factory_client.initialize(&factory_admin);

        let wasm_hash = env.deployer().upload_contract_wasm(STUB_WASM);

        assert!(!factory_client.is_wasm_hash_approved(&wasm_hash));
        factory_client.approve_wasm_hash(&factory_admin, &wasm_hash);
        assert!(factory_client.is_wasm_hash_approved(&wasm_hash));
        factory_client.revoke_wasm_hash(&factory_admin, &wasm_hash);
        assert!(!factory_client.is_wasm_hash_approved(&wasm_hash));
    }
}
