import { Base64 } from "js-base64";
import saslPrep from "saslprep";
import { ScramSha256 } from "./algo/ScramSha256.js";
import { ScramMessageClientFinal } from "./message/ScramMessageClientFinal.js";
import { ScramMessageClientFirst } from "./message/ScramMessageClientFirst.js";
import { ScramMessageServerFinal } from "./message/ScramMessageServerFinal.js";
import { ScramMessageServerFirst } from "./message/ScramMessageServerFirst.js";
import { ScramRequestClient } from "./request/ScramRequestClient.js";
import { ScramRequestServer } from "./request/ScramRequestServer.js";
import { ScramUser } from "./user/ScramUser.js";
import { ScramUserRepo } from "./user/ScramUserRepo.js";
import { RandomSaltGenerator, SaltGenerator } from "./utils/SaltGenerator.js";
import { SCRAM_UNKNOWN_USER, ScramError } from "./utils/ScramError.js";

/**
 * Define the iteration count, generally this will be constant for new registrations with the possibility of
 * incrementing at a later date.
 *
 * This should be as high as tolerable by end users on the average hardware. This example uses 65536 iterations
 * which is decent. This can also be determined per user, so mobile users can use a smaller amount of iterations for
 * login. This value can be cached on the user end, but this comes with it's own security implications.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7677#section-4f
 */
const ITERATIONS = 0x10000;

/**
 * Runs the example authentication exchange
 * @param valid Determines if the example is of a valid authentication, or a failure
 * @returns
 */
export async function runExample() {
    // Pick an algo to use
    const algo = ScramSha256;

    // Server side code:
    // ----------------------

    // Start by creating a user repo and use the SCRAM-SHA-256 algorithm
    const repo = new MyScramUserRepo(new RandomSaltGenerator(ScramSha256, 24));

    // User registration code:
    // -----------------------

    // Get a salt generator for this user. You can either let the client create a salt, or create a salt server-side
    // during a registation handshake.
    const saltGenerator = new RandomSaltGenerator(algo, 24);

    const username = saslPrep("test", { allowUnassigned: true });

    // Generate a salt for this user, and encode with Base64 for storage
    const saltBuffer = await saltGenerator.get(username);
    const salt = Base64.fromUint8Array(saltBuffer);

    // Generate the salted password
    const saltedPassword = await algo.getSaltedPassword("password", saltBuffer, ITERATIONS);

    // Generate a stored key, and encode with Base64 for storage
    const serverKeyBuffer = await algo.getServerKey(saltedPassword);
    const serverKey = Base64.fromUint8Array(serverKeyBuffer);

    // Generate a stored key, and encode with Base64 for storage
    const storedKeyBuffer = await algo.getStoredKey(saltedPassword);
    const storedKey = Base64.fromUint8Array(storedKeyBuffer);

    // Create a test user
    await repo.registerUser(new MyScramUser(username, salt, ITERATIONS, serverKey, storedKey));

    // Now we can create a new ScramRequest for the server
    const serverRequest = new ScramRequestServer(ScramSha256, repo, saltGenerator, ITERATIONS);

    // Client side code:
    // ----------------------
    // Now we can create a new ScramRequest for the server
    const clientRequest = new ScramRequestClient(ScramSha256);

    // We'll begin the SCRAM authentication exchange by creating the client-first-message
    const clientFirstMessage = clientRequest.createClientFirstMessage(username);
    // Normally we'll need get the message in a text-based format for transport
    const clientFirstMessageText = clientFirstMessage.getMessage();
    // This clientFirstMessageText is now sent to the server

    // Server size code:
    // ----------------------

    // We apply the client-first-message to the ScramRequestServer. Since in most situations this will be done between
    // a client and server, we rebuild the ScramMessageClientFirst from text:
    serverRequest.setClientFirstMessage(new ScramMessageClientFirst(clientFirstMessageText));
    // We can now respond with a server-first-message
    const serverFirstMessage = await serverRequest.createServerFirstMessage();
    const serverFirstMessageText = serverFirstMessage.getMessage();
    // This serverFirstMessageText is now sent to the client

    // Client side code:
    // ----------------------

    // We apply the server-first-message to the ScramRequestClient, which allows us to generate our proof and respond
    // with a client-final-message
    clientRequest.setServerFirstMessage(new ScramMessageServerFirst(serverFirstMessageText));
    const clientFinalMessage = await clientRequest.createClientFinalMessage(saltedPassword);
    const clientFinalMessageText = clientFinalMessage.getMessage();
    // This clientFinalMessageText is now sent to the server

    // Server side code:
    // ----------------------

    // We apply the client-final-message to the ScramRequestServer, and generate the server-final-message
    serverRequest.setClientFinalMessage(new ScramMessageClientFinal(clientFinalMessageText));
    const serverFinalMessage = await serverRequest.createServerFinalMessage();
    const serverFinalMessageText = serverFinalMessage.getMessage();

    // Since we've complete the authentication on the server side as this point, we can verify the proof
    if (await serverRequest.verifyClientFinalMessage()) {
        console.log("User has successfully authenticated.");
    } else {
        console.log("User was unable to authenticate.");
    }

    // The server-final-message is now sent to the client

    // Client side code:
    // ----------------------

    // We apply the server-final-message to the client to confirm the server has valid credentials for this user
    clientRequest.setServerFinalMessage(new ScramMessageServerFinal(serverFinalMessageText));
    if (await clientRequest.verifyServerFinalMessage(saltedPassword)) {
        console.log("User identify on the server is valid");
    } else {
        console.log("User identify on the server was invalid");
    }

    return (
        (await serverRequest.verifyClientFinalMessage()) &&
        (await clientRequest.verifyServerFinalMessage(saltedPassword))
    );
}

/**
 * An in-memory user repo to demonstrate simple usage of this package
 */
class MyScramUserRepo implements ScramUserRepo {
    private readonly saltedGenerator: SaltGenerator;
    private users: { [name: string]: MyScramUser } = {};

    constructor(saltGenerator: SaltGenerator) {
        this.saltedGenerator = saltGenerator;
    }

    public async registerUser(user: MyScramUser) {
        this.users[user.getUsername()] = user;
    }

    find(username: string): ScramUser {
        if (this.has(username)) {
            return this.users[username];
        } else {
            throw new ScramError(SCRAM_UNKNOWN_USER);
        }
    }

    has(username: string): boolean {
        return Boolean(this.users[username]);
    }
}

/**
 * An example implementation of MyScramUser. It expects Base64 encoded versions of the `salt`, `serverKey`, and
 * `storedKey` to replicate a standard database storage using strings.
 */
class MyScramUser implements ScramUser {
    private readonly username;
    private readonly salt;
    private readonly iterations;
    private readonly storedKey;
    private readonly serverKey;
    constructor(username: string, salt: string, iterations: number, serverKey: string, storedKey: string) {
        this.username = username;
        this.iterations = iterations;

        // Read the needed salt and keys and decode them for use with the cryptographic functions
        this.salt = Base64.toUint8Array(salt);
        this.serverKey = Base64.toUint8Array(serverKey);
        this.storedKey = Base64.toUint8Array(storedKey);
    }

    getUsername(): string {
        return this.username;
    }

    getSalt(): Uint8Array {
        return this.salt;
    }

    getIterations(): number {
        return this.iterations;
    }

    getServerKey(): Uint8Array {
        return this.serverKey;
    }

    getStoredKey(): Uint8Array {
        return this.storedKey;
    }
}

// Run the example if this file is being called directly
if (require.main === module) {
    runExample();
}
