import { Crypto } from "@peculiar/webcrypto";
import { ScramAlgo } from "../algo/ScramAlgo.js";

/**
 * Used to define a class used to generate user salts. Depending on your security concerns, you can use either the
 * PepperedSaltGenerate, which uses the user's username and a randomly generated global pepper to generate salts
 * in a deterministic manner, or the RandomSaltGenerator which generates truly random salts.
 */
export interface SaltGenerator {
    /**
     * Generates a salt for the given user
     * @param user The username of the ScramUser to generate a salt for
     * @returns An array buffer containing the salt, generally hashed using a ScramAlgo identical to the user's password
     */
    get(username: string): Promise<Uint8Array>;
}

/**
 * A SaltGenerator that uses a static pepper for the application mixed with the username of the user. While this method
 * has the downside of being more deterministic than an purely random salt, it has the upside of allowing the SCRAM to
 * offer consistent salts in the case of an attack on the SCRAM protocol itself. In this scenario, the attacker would
 * be unable to determine accounts validity based on a change in the salt given.
 */
export class PepperedSaltGenerator implements SaltGenerator {
    private readonly algo: ScramAlgo;
    private readonly pepper: string;

    constructor(algo: ScramAlgo, pepper: string) {
        this.algo = algo;
        this.pepper = pepper;
    }

    get(username: string) {
        const message = new TextEncoder().encode(`${username}:${this.pepper}`);
        return this.algo.hash(message);
    }
}

/**
 * A SaltGenerator that provides a purely random salt generated using Crypto.getRandomValues, and then hashed for
 * storage
 */
export class RandomSaltGenerator implements SaltGenerator {
    private readonly algo: ScramAlgo;
    private length: number;

    constructor(algo: ScramAlgo, length: number) {
        this.algo = algo;
        this.length = length;
    }

    async get(username: string) {
        const crypto = new Crypto();
        const buffer = new Uint8Array(this.length);
        crypto.getRandomValues(buffer);
        return this.algo.hash(buffer);
    }
}
