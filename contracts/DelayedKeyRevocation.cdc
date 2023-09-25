/// This contract enables coordination of delayed key revocation by trusted parties. A Grantor can issue Revokable
/// Capabilities on a wrapped account to custodians, and if enough of them authorize a key revocation, the Grantor
/// has the length of the delay to veto the revocation. If gone unchallenged, the Custodian can then execute the
/// revocation, revoking the target key and adding all authorizing keys as equal weighted multisig keys.
///
/// NOTE: This is presented for demonstration purposes and is not sufficiently robust for use in production
///
pub contract DelayedKeyRevocation {

    pub let GrantorStoragePath: StoragePath
    pub let RevokablePrivatePath: PrivatePath
    pub let CustodianStoragePath: StoragePath

    pub event RevocationAuthorized(onAccount: Address, authorizer: Address, grantor: Address, executionTimestamp: UFix64?)
    pub event RevocationVetoed(onAccount: Address, grantor: Address? )
    pub event RevocationExecuted(onAccount: Address, authorizers: [Address])

    /// Struct containing the public key its hash algorithm
    ///
    pub struct CustodianKeyInfo {
        pub let publicKey: PublicKey
        pub let hashAlgorithm: HashAlgorithm

        init(publicKey: PublicKey, hashAlgorithm: HashAlgorithm) {
            self.publicKey = publicKey
            self.hashAlgorithm = hashAlgorithm
        }
    }

    /* --- Grantor --- */
    //
    /// Interface for a Revokable Capability
    ///
    pub resource interface Revokable {
        access(contract) fun revoke(authorizer: Address, keyInfo: CustodianKeyInfo)
        access(contract) fun executeRevocation()
    }
    
    /// Resource containing all data necessary to coordinate a delayed key revocation and rotation
    ///
    pub resource Grantor : Revokable {
        /// Capability on the underlying account this resource coordinates revocation on
        access(self) let accountCapability: Capability<&AuthAccount>
        /// Map of authorizing Custodians to their key information
        access(self) var authorizations: {Address: CustodianKeyInfo}
        /// Number of authorizations before revocation can be executed
        pub let authorizationThreshold: UInt8
        /// Delay from final authorization before revocation can be executed
        pub let revovationDelay: UFix64
        /// Key index to revoke
        pub var targetKeyIndex: Int
        /// Timestamp when authorization threshold was met
        pub var revocationTimestamp: UFix64?
        /// Whether revocation has been completed
        pub var revoked: Bool

        init(
            accountCapability: Capability<&AuthAccount>,
            authorizationThreshold: UInt8,
            revovationDelay: UFix64,
            targetKeyIndex: Int
        ) {
            pre {
                accountCapability.check(): "Invalid account capability"
            }
            self.accountCapability = accountCapability
            self.authorizationThreshold = authorizationThreshold
            self.authorizations = {}
            self.revovationDelay = revovationDelay
            self.targetKeyIndex = targetKeyIndex
            self.revocationTimestamp = nil
            self.revoked = false
        }

        /* Revokable conformance */
        //
        /// Enables a Custodian to authorize a key revocation
        ///
        access(contract) fun revoke(authorizer: Address, keyInfo: CustodianKeyInfo) {
            pre {
                !self.authorizations.containsKey(authorizer): "Cannot duplicate revocation authorizations"
                self.revocationTimestamp == nil: "Revocation has already been initiated"
                self.revoked == false: "Revocation has already been completed"
            }
            self.authorizations.insert(key: authorizer, keyInfo)
            if self.authorizations.length == Int(self.authorizationThreshold) {
                self.revocationTimestamp = getCurrentBlock().timestamp
            }
            emit RevocationAuthorized(
                onAccount: self.borrowAccount().address,
                authorizer: authorizer,
                grantor: self.owner!.address,
                executionTimestamp: self.revocationTimestamp != nil ? self.revocationTimestamp! + self.revovationDelay : nil
            )
        }

        /// Executes a pending revocation if the revocation threshold and time delay has been met
        ///
        access(contract) fun executeRevocation() {
            pre {
                self.revocationTimestamp != nil: "Revocation has not been initiated"
                getCurrentBlock().timestamp >= self.revocationTimestamp! + self.revovationDelay:
                    "Revocation delay has not been met"
            }
            // Revoke the target key
            let account = self.borrowAccount()
            account.keys.revoke(keyIndex: self.targetKeyIndex)

            // Add all the authorizers as equal weighted keys
            let keyWeight = 1000.0 / UFix64(self.authorizations.length)
            for authorizer in self.authorizations.keys {
                let keyInfo = self.authorizations[authorizer]!
                account.keys.add(
                    publicKey: keyInfo.publicKey,
                    hashAlgorithm: keyInfo.hashAlgorithm,
                    weight: keyWeight
                )
            }
            // Mark the grantor as revoked
            self.revoked = true

            emit RevocationExecuted(onAccount: account.address, authorizers: self.authorizations.keys)
        }

        /* Resource Owner functionality */
        //
        /// Enables the resource owner to veto a pending key revocation
        ///
        pub fun veto() {
            pre {
                self.revoked == false: "Revocation has already been completed"
            }
            self.revocationTimestamp = nil
            self.authorizations = {}
            emit RevocationVetoed(onAccount: self.borrowAccount().address, grantor: self.owner?.address)
        }

        /// Updates the target key index to be revoked
        ///
        pub fun updateTargetKeyIndex(to: Int) {
            pre {
                self.revoked == false: "Revocation has already been completed"
            }
            self.targetKeyIndex = to
        }

        /* Helper method */
        //
        /// Helper method to borrow the underlying account object reference
        ///
        access(self) fun borrowAccount(): &AuthAccount {
            return self.accountCapability.borrow() ?? panic("Invalid account capability")
        }
    }

    /* --- Custodian --- */
    //
    /// Custodies a Revokable Capability and enables the owner to authorize a key revocation on the underlying account
    /// with the Custodian's key information
    ///
    pub resource Custodian {
        /// Capability on the underlying Revokable resource
        pub var revokableCapability: Capability<&{Revokable}>
        /// Key information to pass when authorizing revocation
        pub let keyInfo: CustodianKeyInfo

        init(revokableCapability: Capability<&{Revokable}>, keyInfo: CustodianKeyInfo) {
            pre {
                revokableCapability.check(): "Invalid grantor capability"
            }
            self.revokableCapability = revokableCapability
            self.keyInfo = keyInfo
        }

        /// Authorizes revocation and passes custodian's key information
        ///
        pub fun authorizeRevocation() {
            self.borrowRevokable().revoke(authorizer: self.owner!.address, keyInfo: self.keyInfo)
        }

        /// Executes a pending revocation if the revocation threshold and time delay has been met
        ///
        pub fun executeRevocation() {
            self.borrowRevokable().executeRevocation()
        }

        /// Helper method retrieving a reference to the Revokable resource
        /// 
        access(self) fun borrowRevokable(): &{Revokable} {
            return self.revokableCapability.borrow() ?? panic("Invalid grantor capability")
        }
    }

    /// Creates a new Grantor resource
    ///
    pub fun createNewGrantor(
        accountCapability: Capability<&AuthAccount>,
        authorizationThreshold: UInt8,
        revovationDelay: UFix64,
        targetKeyIndex: Int
    ): @Grantor {
        return <-create Grantor(
            accountCapability: accountCapability,
            authorizationThreshold: authorizationThreshold,
            revovationDelay: revovationDelay,
            targetKeyIndex: targetKeyIndex
        )
    }

    /// Creates a new Custodian resource
    ///
    pub fun createNewCustodian(revokableCapability: Capability<&{Revokable}>, keyInfo: CustodianKeyInfo): @Custodian {
        return <-create Custodian(revokableCapability: revokableCapability, keyInfo: keyInfo)
    }

    init() {
        self.GrantorStoragePath = /storage/DelayedKeyRevocationGrantor
        self.RevokablePrivatePath = /private/DelayedKeyRevocationRevokable
        self.CustodianStoragePath = /storage/DelayedKeyRevocationCustodian
    }
}