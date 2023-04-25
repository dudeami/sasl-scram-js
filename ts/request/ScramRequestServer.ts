import { Crypto } from "@peculiar/webcrypto";
import { Base64 } from "js-base64";
import { ScramAlgo } from "../algo/ScramAlgo.js";
import { ScramMessageServerFinal } from "../message/ScramMessageServerFinal.js";
import { ScramMessageServerFirst } from "../message/ScramMessageServerFirst.js";
import { ScramUser } from "../user/ScramUser.js";
import { ScramUserRepo } from "../user/ScramUserRepo.js";
import { SaltGenerator } from "../utils/SaltGenerator.js";
import {
    SCRAM_CHANNEL_BINDING_NOT_SUPPORTED,
    SCRAM_EXTENSIONS_NOT_SUPPORTED,
    SCRAM_INVALID_PROOF,
    SCRAM_OTHER_ERROR,
    ScramError,
} from "../utils/ScramError.js";
import { xorArrayBuffer } from "../utils/xorArrayBuffer.js";
import { ScramRequest } from "./ScramRequest.js";

/**
 * The options for a `ScramRequestServer`
 */
export interface ScramRequestServerOptions {
    /**
     * If true, conceals errors by returning all errors as `other-error`.
     */
    concealErrors?: boolean;
}

/**
 * The config for a `ScramRequestServer`, with no optional parameters.
 */
export interface ScramRequestServerConfig {
    concealErrors: boolean;
}

/**
 * The default config for a `ScramRequestServer`
 */
const DEFAULT_CONFIG: ScramRequestServerConfig = {
    concealErrors: false,
};

/**
 * Represents a SCRAM authentication exchange on the server side.
 */
export class ScramRequestServer extends ScramRequest {
    private readonly repo: ScramUserRepo;
    private readonly saltGenerator: SaltGenerator;
    private readonly iterations: number;
    private readonly options: ScramRequestServerConfig;

    /**
     * Initializes a SCRAM authentication exchange on the server side.
     * @param algo The SCRAM algorithm to be used
     * @param repo A `ScramUserRepo` allowing access to users
     * @param saltGenerator A `SaltGenerator` that allows salts to be generated in the case a user does not exist
     * @param iterations The default iteration count for any user that does not exist
     * @param options Optional config values
     */
    constructor(
        algo: ScramAlgo,
        repo: ScramUserRepo,
        saltGenerator: SaltGenerator,
        iterations: number,
        options: ScramRequestServerOptions = {}
    ) {
        super(algo);
        this.repo = repo;
        this.saltGenerator = saltGenerator;
        this.iterations = iterations;
        this.options = Object.assign({}, DEFAULT_CONFIG, options);
    }

    /**
     * Given a `client-first-message` has been added to the request, creates a server-first-message for this request.
     * @returns A `ScramMessageServerFirst` representing the server-first-message
     */
    public async createServerFirstMessage() {
        if (this.clientFirstMessage) {
            const username = this.clientFirstMessage.getUser();
            const c_nonce = this.clientFirstMessage.getNonce();

            let salt;
            let iterations;
            if (this.repo.has(username)) {
                const user = this.repo.find(username);
                salt = user.getSalt();
                iterations = user.getIterations();
            } else {
                salt = await this.saltGenerator.get(username);
                iterations = this.iterations;
            }

            const encodedSalt = Base64.fromUint8Array(salt);

            const randomBuffer = new Uint8Array(24);
            new Crypto().getRandomValues(randomBuffer);
            const s_nonce = Base64.fromUint8Array(randomBuffer);
            const nonce = c_nonce + s_nonce;

            this.serverFirstMessage = new ScramMessageServerFirst(`r=${nonce},s=${encodedSalt},i=${iterations}`);
            return this.serverFirstMessage;
        } else {
            throw new Error("Unable to create server-first-message, missing client-first-message.");
        }
    }

    /**
     * Given a `client-first-message`, `server-first-message, and `client-final-message` has been added to the request,
     * creates a server-final-message for this request.
     * @returns A `ScramMessageServerFinal` representing the server-final-message
     */
    public async createServerFinalMessage() {
        if (this.clientFirstMessage && this.serverFirstMessage && this.clientFinalMessage) {
            const username = this.clientFirstMessage.getUser();

            try {
                if (this.clientFirstMessage.getMext()) {
                    throw new ScramError(SCRAM_EXTENSIONS_NOT_SUPPORTED);
                }
                if (this.clientFirstMessage.getGS2CbindFlag() !== "n") {
                    throw new ScramError(SCRAM_CHANNEL_BINDING_NOT_SUPPORTED);
                }

                const user = this.repo.find(username);
                const serverKey = user.getServerKey();
                const authMessage = this.getAuthMessage(this.clientFinalMessage.getMessageWithoutProof());

                const proof = Base64.fromUint8Array(new Uint8Array(await this.algo.hmac(serverKey, authMessage)));
                if (!(await this.verifyClientFinalMessage())) {
                    throw new ScramError(SCRAM_INVALID_PROOF);
                } else {
                    this.serverFinalMessage = new ScramMessageServerFinal(`v=${proof}`);
                }
            } catch (e) {
                let error: ScramError = <ScramError>e;
                this.serverFinalMessage = new ScramMessageServerFinal(
                    this.options.concealErrors ? `e=${SCRAM_OTHER_ERROR}` : `e=${error.errorCode}`
                );
            }
            return this.serverFinalMessage;
        } else {
            throw new Error(
                "Unable to create server-final-message, missing client-first-message, server-first-message, or client-final-message."
            );
        }
    }

    /**
     * Given a `client-first-message`, `server-first-message, and `client-final-message` has been added to the request,
     * verifys the client proof is valid.
     * @returns `true` if the client proof is valid, otherwise `false`
     */
    public async verifyClientFinalMessage() {
        if (this.clientFirstMessage && this.serverFirstMessage && this.clientFinalMessage) {
            const username = this.clientFirstMessage.getUser();
            if (!this.repo.has(username)) {
                return false;
            }

            const user = <ScramUser>this.repo.find(username);
            const clientProof = Base64.toUint8Array(this.clientFinalMessage.getClientProof());
            const storedKey = user.getStoredKey();
            const authMessage = this.getAuthMessage(this.clientFinalMessage.getMessageWithoutProof());
            const clientSignature = await this.algo.hmac(storedKey, authMessage);
            const clientKey = xorArrayBuffer(clientSignature, clientProof);

            return Base64.fromUint8Array(storedKey) === Base64.fromUint8Array(await this.algo.hash(clientKey));
        } else {
            throw new Error(
                "Unable to verify client-final-message, missing client-first-message, server-first-message, or client-final-message."
            );
        }
    }
}
