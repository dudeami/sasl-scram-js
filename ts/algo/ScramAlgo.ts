import { Crypto } from "@peculiar/webcrypto";
import saslPrep from "saslprep";

/**
 * Provides access to cryptographic functions required to compute SCRAM messages.
 */
export class ScramAlgo {
    /**
     * WebCrypto API algorithm name.
     */
    private readonly algo: string;
    /**
     * Key length of the resulting hash of the algorithm.
     */
    private readonly keylen: number;

    /**
     * Creates a new ScramAlgo instance for the given algorithm and keylength.
     * @param algo
     * @param keylen
     */
    constructor(algo: string, keylen: number) {
        this.algo = algo;
        this.keylen = keylen;
    }

    /**
     * Hashes a password with PBKDF2 using the algorithm defined for this instance
     * @param password Password to be hashed
     * @param salt Salt to use when hashing the password
     * @param iterations The number of iterations to perform. Consult RFC 7677 for security considerations.
     * @link https://datatracker.ietf.org/doc/html/rfc7677#section-4
     * @returns An Uint8Array with the results of the PBKDF2 algorithm
     */
    public async pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number) {
        const crypto = new Crypto();
        const keyMaterial = await crypto.subtle.importKey("raw", password, "PBKDF2", false, [
            "deriveBits",
            "deriveKey",
        ]);

        const result = await crypto.subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: salt,
                iterations,
                hash: this.algo,
            },
            keyMaterial,
            this.keylen
        );

        return new Uint8Array(result);
    }

    /**
     * Performas a HMAC hash using the algorithm defined for this instance
     * @param text The text to be hashed
     * @param secret The secret to use with the HMAC algorithm
     * @returns An Uint8Array with the results of the HMAC algorithm
     */
    public async hmac(message: Uint8Array, secret: Uint8Array) {
        const crypto = new Crypto();
        const messageKey = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: this.algo }, false, [
            "sign",
            "verify",
        ]);
        return new Uint8Array(await crypto.subtle.sign("HMAC", messageKey, message));
    }

    /**
     * Performs a standard cryptographic hash using the algorithm defined for this instance
     * @param text The text to be hashed
     * @returns An Uint8Array with the results of the hash algorithm
     */
    public async hash(text: Uint8Array) {
        const crypto = new Crypto();
        return new Uint8Array(await crypto.subtle.digest(this.algo, text));
    }

    /**
     * Salts and hashes  a password with PBKDF2 according to SCRAM specifications.
     * @param password The cleartext password to be salted
     * @param salt A Uint8Array of random bytes
     * @param iterations Number of iterations to be used for this password
     * @returns Uint8Array containing the salted password
     */
    public async getSaltedPassword(password: string, salt: Uint8Array, iterations: number) {
        const prepedPassword = saslPrep(password, { allowUnassigned: true });
        return await this.pbkdf2(new TextEncoder().encode(prepedPassword), salt, iterations);
    }

    /**
     * Creates the ClientKey for the given salted password.
     * @param saltedPassword The salted password to create the ClientKey with
     * @returns Uint8Array containing the ClientKey
     */
    public async getClientKey(saltedPassword: Uint8Array) {
        return this.hmac(saltedPassword, new TextEncoder().encode("Client Key"));
    }

    /**
     * Creates the StoredKey for the given saltedPassword.
     * @param saltedPassword The salted password to create the StoredKey with
     * @returns Uint8Array containing the StoredKey
     */
    public async getStoredKey(saltedPassword: Uint8Array) {
        return this.hash(await this.getClientKey(saltedPassword));
    }

    /**
     * Creates the ServerKey for the given saltedPassword.
     * @param saltedPassword The salted password to create the ServerKey with
     * @returns Uint8Array containing the ServerKey
     */
    public async getServerKey(saltedPassword: Uint8Array) {
        return this.hmac(saltedPassword, new TextEncoder().encode("Server Key"));
    }

    /**
     * Provides the algorithm name
     * @returns The algorithm name
     */
    public getName() {
        return this.algo;
    }
}
