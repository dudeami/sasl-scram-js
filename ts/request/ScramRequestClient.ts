import { Crypto } from "@peculiar/webcrypto";
import { Base64 } from "js-base64";
import { ScramAlgo } from "../algo/ScramAlgo.js";
import { ScramMessageClientFinal } from "../message/ScramMessageClientFinal.js";
import { ScramMessageClientFirst } from "../message/ScramMessageClientFirst.js";
import { xorArrayBuffer } from "../utils/xorArrayBuffer.js";
import { ScramRequest } from "./ScramRequest.js";

/**
 * The options for a `ScramRequestServer`
 */
export interface ScramRequestClientOptions {
    /**
     * The maximum allowed iterations from the server. This should be set to something reasonable that won't run for
     * multiple seconds to prevent server-sided attacks against clients.
     */
    maxIterations?: number;
}

/**
 * The config for a `ScramRequestServer`, with no optional parameters.
 */
export interface ScramRequestClientConfig {
    maxIterations: number;
}

/**
 * The default config for a `ScramRequestServer`
 */
const DEFAULT_CONFIG: ScramRequestClientConfig = {
    maxIterations: 0xffffff,
};

/**
 * Represents a SCRAM authentication exchange on the client side.
 */
export class ScramRequestClient extends ScramRequest {
    private readonly gs2_header: string;
    private readonly options: ScramRequestClientConfig;

    /**
     * Initializes a SCRAM authentication exchange on the server side.
     * @param algo The SCRAM algorithm to be used
     */
    constructor(algo: ScramAlgo, options: ScramRequestClientOptions = {}) {
        super(algo);
        this.gs2_header = `n,`;
        this.options = Object.assign({}, DEFAULT_CONFIG, options);
    }

    /**
     * Given a `client-first-message` and `server-first-message` have been added to the request, allows for a password
     * to be salted and hashed into a salted password.
     * @param password The cleartext password to be salted
     * @returns A salted password
     */
    public async getSaltedPassword(password: string) {
        if (this.clientFirstMessage && this.serverFirstMessage) {
            const salt = this.serverFirstMessage.getSalt();
            const iterations = this.serverFirstMessage.getIterations();
            if (iterations > this.options.maxIterations) {
                throw new Error(`Iteration count of ${iterations} exceeed maximum of ${this.options.maxIterations}`);
            }
            return await this.algo.pbkdf2(new TextEncoder().encode(password), salt, iterations);
        } else {
            throw new Error("Unable to create salted password, missing client-first-message or server-first-message.");
        }
    }

    /**
     * Creates the initial client-first-message in a SCRAM authentication exchange.
     * @param user The name of the user to authenticate as
     * @returns A `ScramMessageClientFirst` representation of the client-first-message
     */
    public createClientFirstMessage(user: string) {
        const randomBuffer = new Uint8Array(24);
        new Crypto().getRandomValues(randomBuffer);
        const c_nonce = Base64.fromUint8Array(randomBuffer);
        this.clientFirstMessage = new ScramMessageClientFirst(`${this.gs2_header},n=${user},r=${c_nonce}`);
        return this.clientFirstMessage;
    }

    /**
     * Given a `client-first-message` and `server-first-message` have been added to the request, creates the
     * client-final-message for this SCRAM authentication exchange.
     * @param saltedPassword A `Uint8Array` containing the salted password
     * @returns A `ScramMessageClientFinal` represention of the client-final-message
     */
    public async createClientFinalMessage(saltedPassword: Uint8Array) {
        if (this.clientFirstMessage && this.serverFirstMessage) {
            const clientKey = await this.algo.getClientKey(saltedPassword);
            const storedKey = await this.algo.getStoredKey(saltedPassword);

            const gs2header = Base64.encode(this.gs2_header + ",");
            const nonce = this.serverFirstMessage.getNonce();
            const clientFinalWithoutProof = `c=${gs2header},r=${nonce}`;
            const authMessage = this.getAuthMessage(clientFinalWithoutProof);

            const clientSignature = await this.algo.hmac(storedKey, authMessage);
            const proof = Base64.fromUint8Array(xorArrayBuffer(clientKey, clientSignature));
            this.clientFinalMessage = new ScramMessageClientFinal(`${clientFinalWithoutProof},p=${proof}`);
            return this.clientFinalMessage;
        } else {
            throw new Error(
                "Unable to create client-final-message, missing client-first-message or server-first-message."
            );
        }
    }

    /**
     * Given all messages (`client-first-message`, `server-first-message`, `client-final-message`,
     * `server-final-message`) have been added to the request, validates the servers verifier for mutual authentication.
     * @param saltedPassword The salted password, see `ScramRequestClient.getSaltedPassword`
     * @returns `true` if the server verifier is valid, other false.
     */
    public async verifyServerFinalMessage(saltedPassword: Uint8Array) {
        if (this.clientFirstMessage && this.serverFirstMessage && this.clientFinalMessage && this.serverFinalMessage) {
            const serverKey = await this.algo.getServerKey(saltedPassword);
            const authMessage = this.getAuthMessage(this.clientFinalMessage.getMessageWithoutProof());

            const proof = Base64.fromUint8Array(new Uint8Array(await this.algo.hmac(serverKey, authMessage)));

            return this.serverFinalMessage.getVerifier() === proof;
        } else {
            throw new Error(
                "Unable to verify server-final-message, missing client-first-message, server-first-message, client-final-message or server-final-message."
            );
        }
    }
}
