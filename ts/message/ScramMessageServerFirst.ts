import { Base64 } from "js-base64";
import { readScramParamString } from "./readParamString.js";

/**
 * Reads and provides data related to a server-first-message as defined by SCRAM
 */
export class ScramMessageServerFirst {
    /**
     * The full original text of the server-first-message
     */
    private readonly message: string;
    /**
     * The full (server + client) nonce for this SCRAM authentication exchange
     */
    private readonly nonce: string;
    /**
     * The salt to be used for this authentication request
     */
    private readonly salt: Uint8Array;
    /**
     * The number of iterations to be used with for this authentication request
     */
    private readonly iterations: number;

    /**
     * Parses a server-first-message
     * @param message The server-first-message to parse
     */
    constructor(message: string) {
        this.message = message;
        const params = readScramParamString(message);

        if (!params["r"] || !params["s"] || !params["i"]) {
            throw new Error("Unable to read server-first-message");
        }

        this.nonce = params["r"];
        this.salt = Base64.toUint8Array(params["s"]);
        this.iterations = parseInt(params["i"]);

        if (isNaN(this.iterations)) {
            throw new Error("Unable to read server-first-message");
        }
    }

    /**
     * @return The full original text of the server-first-message
     */
    public getMessage() {
        return this.message;
    }

    /**
     * @return The full (server + client) nonce for this SCRAM authentication exchange
     */
    public getNonce() {
        return this.nonce;
    }

    /**
     * @return The salt to be used for this authentication request
     */
    public getSalt() {
        return this.salt;
    }

    /**
     * @return The number of iterations to be used with for this authentication request
     */
    public getIterations() {
        return this.iterations;
    }
}
