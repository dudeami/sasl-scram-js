/**
 * A user that can be authenticated via the SCRAM algorithm
 */
export interface ScramUser {
    /**
     * Username of this scram user
     */
    getUsername(): string;
    /**
     * The cryptographic salt for this user
     */
    getSalt(): Uint8Array;

    /**
     * The iteration count used when hashing this user's password
     */
    getIterations(): number;

    /**
     * The `ServerKey` for this user per the SCRAM specs
     */
    getServerKey(): Uint8Array;

    /**
     * The `StoredKey` for this user per the SCRAM specs
     */
    getStoredKey(): Uint8Array;
}
