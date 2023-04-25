import { readScramParamString } from "./readParamString.js";

/**
 * Reads and provides data of a client-final-message as defined by SCRAM
 */
export class ScramMessageClientFinal {
    /**
     * The full original text of the client-final-message
     */
    private readonly message: string;
    /**
     * The original client-final-message text omitting the client proof
     */
    private readonly messageWithoutProof: string;
    /**
     * The GS2 header encoded in Base64
     */
    private readonly gs2Header: string;
    /**
     * The full (server + client) nonce for this SCRAM authentication exchange
     */
    private readonly nonce: string;
    /**
     * The client proof encoded in Base64
     */
    private readonly clientProof: string;

    /**
     * Parses a client-final-message
     * @param message The client-final-message to parse
     */
    constructor(message: string) {
        this.message = message;

        const [clientFinalWithoutProof, proof] = message.split(",p=");
        this.messageWithoutProof = clientFinalWithoutProof;
        this.clientProof = proof;

        const params = readScramParamString(clientFinalWithoutProof);
        this.gs2Header = params["c"];
        this.nonce = params["r"];

        if (!this.gs2Header || !this.nonce || !this.messageWithoutProof || !this.clientProof) {
            throw new Error("Unable to read client-final-message");
        }
    }

    /**
     * @returns The original client-final-message
     */
    public getMessage() {
        return this.message;
    }

    /**
     * @returns The original client-final-message, omitting the client proof
     */
    public getMessageWithoutProof() {
        return this.messageWithoutProof;
    }

    /**
     * @returns Base64 encoded GS2 header
     */
    public getGS2Header() {
        return this.gs2Header;
    }

    /**
     * @returns Combined client and server nonce
     */
    public getNonce() {
        return this.nonce;
    }

    /**
     * @returns Base64 encoded client proof
     */
    public getClientProof() {
        return this.clientProof;
    }
}
