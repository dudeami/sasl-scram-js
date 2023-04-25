import saslPrep from "saslprep";
import { readScramParamString } from "./readParamString.js";

/**
 * Reads and provides data related to a client-first-message as defined by SCRAM
 */
export class ScramMessageClientFirst {
    /**
     * The full original text of the client-first-message
     */
    private readonly message: string;
    /**
     * The original text of the client-first-message, omitting the GS2 header
     */
    private readonly messageBare: string;
    /**
     * The username of the authenticating user encoded in UTF-8
     */
    private readonly user: string;
    /**
     * The GS2 channel-binding flag
     */
    private readonly gs2CbindFlag: string;
    /**
     * The client nonce, encoded in Base64
     */
    private readonly nonce: string;
    /**
     * The reserved "m" or "mext" extension
     */
    private readonly mext: string;

    /**
     * Parses a client-first-message
     * @param message The client-first-message to parse
     */
    constructor(message: string) {
        this.message = message;

        const index = message.indexOf(",", message.indexOf(",") + 1) + 1;
        const [gs2CbindFlag, authzid] = message.substring(0, index).split(",");
        this.messageBare = message.substring(index);
        const params = readScramParamString(message);

        if (!params["n"]) {
            throw new Error("Unable to read client-first-message");
        }

        this.gs2CbindFlag = gs2CbindFlag;
        this.nonce = params["r"];
        this.mext = params["m"];
        this.user = saslPrep(params["n"], { allowUnassigned: true });

        if (!this.nonce || !this.user || !this.gs2CbindFlag) {
            throw new Error("Unable to read client-first-message");
        }
    }

    /**
     * @returns The full original text of the client-first-message
     */
    public getMessage() {
        return this.message;
    }

    /**
     * @returns The original text of the client-first-message, omitting the GS2 header
     */
    public getMessageBare() {
        return this.messageBare;
    }

    /**
     * @returns The username of the authenticating user encoded in UTF-8
     */
    public getUser() {
        return this.user;
    }

    /**
     * @returns The GS2 channel-binding flag
     */
    public getGS2CbindFlag() {
        return this.gs2CbindFlag;
    }
    /**
     * @returns The client nonce, encoded in Base64
     */
    public getNonce() {
        return this.nonce;
    }

    /**
     * @returns The reserved mext extension.
     */
    public getMext() {
        return this.mext;
    }
}
