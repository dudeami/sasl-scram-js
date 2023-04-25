import { ScramAlgo } from "../algo/ScramAlgo.js";
import { ScramMessageClientFinal } from "../message/ScramMessageClientFinal.js";
import { ScramMessageClientFirst } from "../message/ScramMessageClientFirst.js";
import { ScramMessageServerFinal } from "../message/ScramMessageServerFinal.js";
import { ScramMessageServerFirst } from "../message/ScramMessageServerFirst.js";

/**
 * Represents the base of a SCRAM authentication exchange, and provides shared methods related to creating messages.
 */
export abstract class ScramRequest {
    /**
     * The SCRAM algo used by this request
     */
    protected readonly algo: ScramAlgo;

    /**
     * The client-first-message of this authenticatione exchange
     */
    protected clientFirstMessage?: ScramMessageClientFirst;

    /**
     * The client-final-message of this authenticatione exchange
     */
    protected clientFinalMessage?: ScramMessageClientFinal;

    /**
     * The server-first-message of this authenticatione exchange
     */
    protected serverFirstMessage?: ScramMessageServerFirst;

    /**
     * The server-final-message of this authenticatione exchange
     */
    protected serverFinalMessage?: ScramMessageServerFinal;

    /**
     * Creates a new SCRAM request
     * @param algo SCRAM algorithm to be used in this request
     */
    constructor(algo: ScramAlgo) {
        this.algo = algo;
    }

    /**
     * Sets the client-first-message for this request
     * @param message A `ScramMessageClientFirst`
     */
    public setClientFirstMessage(message: ScramMessageClientFirst) {
        this.clientFirstMessage = message;
    }

    /**
     * Provides access to the client-first-message for this request
     * @returns Wrapped client-first-message for this request
     */
    public getClientFirstMessage() {
        return this.clientFirstMessage;
    }

    /**
     * Sets the client-final-message for this request
     * @param message A `ScramMessageClientFinal`
     */
    public setClientFinalMessage(message: ScramMessageClientFinal) {
        this.clientFinalMessage = message;
    }

    /**
     * Provides access to the client-final-message for this request
     * @returns Wrapped client-final-message for this request
     */
    public getClientFinalMessage() {
        return this.clientFinalMessage;
    }

    /**
     * Sets the server-first-message for this request
     * @param message A `ScramMessageServerFirst` or a string representing a server-first-message
     */
    public setServerFirstMessage(message: ScramMessageServerFirst) {
        this.serverFirstMessage = message;
    }

    /**
     * Provides access to the server-first-message for this request
     * @returns Wrapped server-first-message for this request
     */
    public getServerFirstMessage() {
        return this.serverFirstMessage;
    }

    /**
     * Sets the server-final-message for this request
     * @param message A `ScramMessageServerFinal` or a string representing a server-final-message
     */
    public setServerFinalMessage(message: ScramMessageServerFinal) {
        this.serverFinalMessage = message;
    }

    /**
     * Provides access to the server-final-message for this request
     * @returns Wrapped server-final-message for this request
     */
    public getServerFinalMessage() {
        return this.serverFinalMessage;
    }

    /**
     * Constructs the auth-message for this request from the first messages of the client and server, and the provided
     * client-final-message-without-proof
     * @param clientFinalWithoutProof The client-final-message-without-proof
     * @returns A Uint8Array of the auth-message for use with cryptographic methods
     */
    protected getAuthMessage(clientFinalWithoutProof: string) {
        return new TextEncoder().encode(
            [
                (<ScramMessageClientFirst>this.clientFirstMessage).getMessageBare(),
                (<ScramMessageServerFirst>this.serverFirstMessage).getMessage(),
                clientFinalWithoutProof,
            ].join(",")
        );
    }
}
