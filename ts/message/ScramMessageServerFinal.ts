import { readScramParamString } from "./readParamString.js";

/**
 * Reads and provides data related to a server-final-message as defined by SCRAM
 */
export class ScramMessageServerFinal {
    /**
     * The full original text of the server-final-message
     */
    private readonly message: string;
    /**
     * The error provided by the server-final-message, or false
     */
    private readonly error: string | false;
    /**
     * The verifier provided by the server-final-message, or false
     */
    private readonly verifier: string | false;

    /**
     * Parses a server-final-message
     * @param message The server-final-message to parse
     */
    constructor(message: string) {
        this.message = message;

        const params = readScramParamString(message);

        this.error = params["e"] || false;
        this.verifier = params["v"] || false;

        if (!this.error && !this.verifier) {
            throw new Error("Unable to read server-final-message");
        }
    }

    /**
     * @returns The full original text of the server-final-message
     */
    public getMessage() {
        return this.message;
    }

    /**
     * @returns The error provided by the server-final-message, or false
     */
    public getError() {
        return this.error;
    }

    /**
     * @returns The verifier provided by the server-final-message, or false
     */
    public getVerifier() {
        return this.verifier;
    }
}
