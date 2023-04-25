import chai from "chai";
import chaiAsPromised from "chai-as-promised";
import saslPrep from "saslprep";
import { ScramAlgo } from "../algo/ScramAlgo.js";
import { ScramSha1 } from "../algo/ScramSha1.js";
import { ScramSha256 } from "../algo/ScramSha256.js";
import { ScramSha384 } from "../algo/ScramSha384.js";
import { ScramSha512 } from "../algo/ScramSha512.js";
import { ScramMessageClientFirst } from "../message/ScramMessageClientFirst.js";
import { ScramRequestClient } from "../request/ScramRequestClient.js";
import { ScramRequestServer } from "../request/ScramRequestServer.js";
import { PepperedSaltGenerator } from "../utils/SaltGenerator.js";
import { SCRAM_CHANNEL_BINDING_NOT_SUPPORTED } from "../utils/ScramError.js";
import { MockScramUser } from "./MockScramUser.js";
import { MockScramUserRepo } from "./MockScramUserRepo.js";

chai.use(chaiAsPromised);

describe(`ScramRequest tests`, () => {
    [ScramSha1, ScramSha256, ScramSha384, ScramSha512].forEach((algo: ScramAlgo) => {
        const iterations = 0x1000;
        const password = "password-´½";
        const username = saslPrep("username-à´½", { allowUnassigned: true });

        const saltGenerator = new PepperedSaltGenerator(ScramSha256, "this-should-be-very-random-and-big");
        let repo: MockScramUserRepo;
        let saltedPassword: Uint8Array;

        async function registerUser(
            username: string,
            salt: Uint8Array,
            saltedPassword: Uint8Array,
            iterations: number
        ) {
            const preppedUsername = saslPrep(username, { allowUnassigned: true });
            const serverKey = await algo.getServerKey(saltedPassword);
            const storedKey = await algo.getStoredKey(saltedPassword);

            await repo.addUser(new MockScramUser(preppedUsername, salt, iterations, storedKey, serverKey));
        }

        before(async () => {
            const salt = await saltGenerator.get(username);
            saltedPassword = await algo.getSaltedPassword(password, salt, iterations);
            repo = new MockScramUserRepo(saltGenerator);
            await registerUser(username, salt, saltedPassword, iterations);
        });

        it(`${algo.getName()}: handles a standard authentication exchange`, async () => {
            const client = new ScramRequestClient(algo);
            const server = new ScramRequestServer(algo, repo, saltGenerator, iterations);
            const clientFirstMessage = client.createClientFirstMessage(username);

            server.setClientFirstMessage(clientFirstMessage);
            chai.assert(server.getClientFirstMessage() === clientFirstMessage);

            const serverFirstMessage = await server.createServerFirstMessage();

            client.setServerFirstMessage(serverFirstMessage);
            chai.assert(client.getServerFirstMessage() === serverFirstMessage);

            const clientFinalMessage = await client.createClientFinalMessage(saltedPassword);

            server.setClientFinalMessage(clientFinalMessage);
            chai.assert(server.getClientFinalMessage() === clientFinalMessage);

            const serverFinalMessage = await server.createServerFinalMessage();

            client.setServerFinalMessage(serverFinalMessage);
            chai.assert(client.getServerFinalMessage() === serverFinalMessage);

            chai.assert(await server.verifyClientFinalMessage());
            chai.assert(await client.verifyServerFinalMessage(saltedPassword));
        });

        it(`${algo.getName()}: errors on an incorrect password`, async () => {
            const client = new ScramRequestClient(algo);
            const server = new ScramRequestServer(algo, repo, saltGenerator, iterations);
            const clientFirstMessage = client.createClientFirstMessage(username);

            server.setClientFirstMessage(clientFirstMessage);
            const serverFirstMessage = await server.createServerFirstMessage();

            client.setServerFirstMessage(serverFirstMessage);
            const clientFinalMessage = await client.createClientFinalMessage(await client.getSaltedPassword("wrong"));

            server.setClientFinalMessage(clientFinalMessage);
            const serverFinalMessage = await server.createServerFinalMessage();

            chai.assert(serverFinalMessage.getError() === "invalid-proof");

            client.setServerFinalMessage(serverFinalMessage);
            chai.assert(!(await server.verifyClientFinalMessage()));
            chai.assert(!(await client.verifyServerFinalMessage(await client.getSaltedPassword("wrong"))));
        });

        if (algo !== ScramSha512) {
            return;
        }

        it(`returns error on user not found`, async () => {
            const client = new ScramRequestClient(algo);
            const server = new ScramRequestServer(algo, repo, saltGenerator, iterations);
            const clientFirstMessage = client.createClientFirstMessage("invalid-user");

            server.setClientFirstMessage(clientFirstMessage);
            const serverFirstMessage = await server.createServerFirstMessage();

            client.setServerFirstMessage(serverFirstMessage);
            const clientFinalMessage = await client.createClientFinalMessage(saltedPassword);

            server.setClientFinalMessage(clientFinalMessage);
            const serverFinalMessage = await server.createServerFinalMessage();

            chai.assert(serverFinalMessage.getError() === "unknown-user");
            chai.assert((await server.verifyClientFinalMessage()) === false);
        });

        it(`returns extensions-not-supported when the "m" extension is used`, async () => {
            const client = new ScramRequestClient(algo);
            const server = new ScramRequestServer(algo, repo, saltGenerator, iterations);
            const clientFirstMessage = new ScramMessageClientFirst(
                "n,,m=invalid,n=username,r=fyko+d2lbbFgONRv9qkxdawL"
            );

            (<any>client).clientFirstMessage = clientFirstMessage;

            server.setClientFirstMessage(clientFirstMessage);
            const serverFirstMessage = await server.createServerFirstMessage();

            client.setServerFirstMessage(serverFirstMessage);
            const clientFinalMessage = await client.createClientFinalMessage(saltedPassword);

            server.setClientFinalMessage(clientFinalMessage);
            const serverFinalMessage = await server.createServerFinalMessage();

            chai.assert(serverFinalMessage.getError() === "extensions-not-supported");
        });

        it(`conceals errors when configured to do so`, async () => {
            const client = new ScramRequestClient(algo);
            const server = new ScramRequestServer(algo, repo, saltGenerator, iterations, { concealErrors: true });
            const clientFirstMessage = client.createClientFirstMessage("invalid-user");

            server.setClientFirstMessage(clientFirstMessage);
            const serverFirstMessage = await server.createServerFirstMessage();

            client.setServerFirstMessage(serverFirstMessage);
            const clientFinalMessage = await client.createClientFinalMessage(saltedPassword);

            server.setClientFinalMessage(clientFinalMessage);
            const serverFinalMessage = await server.createServerFinalMessage();

            chai.assert(serverFinalMessage.getError() === "other-error");
        });

        it(`errors when not applying messages to Server or Client`, async () => {
            const client = new ScramRequestClient(algo);
            const server = new ScramRequestServer(algo, repo, saltGenerator, iterations);
            const clientFirstMessage = client.createClientFirstMessage(username);

            chai.expect(server.createServerFirstMessage()).to.be.rejectedWith(
                Error,
                "Unable to create server-first-message, missing client-first-message."
            );

            server.setClientFirstMessage(clientFirstMessage);
            const serverFirstMessage = await server.createServerFirstMessage();

            chai.expect(client.getSaltedPassword(password)).to.be.rejectedWith(
                Error,
                "Unable to create salted password, missing client-first-message or server-first-message."
            );

            chai.expect(client.createClientFinalMessage(saltedPassword)).to.be.rejectedWith(
                Error,
                "Unable to create client-final-message, missing client-first-message or server-first-message."
            );

            client.setServerFirstMessage(serverFirstMessage);
            const clientFinalMessage = await client.createClientFinalMessage(saltedPassword);

            chai.expect(server.createServerFinalMessage()).to.be.rejectedWith(
                Error,
                "Unable to create server-final-message, missing client-first-message, server-first-message, or client-final-message."
            );

            chai.expect(server.verifyClientFinalMessage()).to.be.rejectedWith(
                Error,
                "Unable to verify client-final-message, missing client-first-message, server-first-message, or client-final-message."
            );

            server.setClientFinalMessage(clientFinalMessage);
            const serverFinalMessage = await server.createServerFinalMessage();

            chai.expect(client.verifyServerFinalMessage(saltedPassword)).to.be.rejectedWith(
                Error,
                "Unable to verify server-final-message, missing client-first-message, server-first-message, client-final-message or server-final-message."
            );

            client.setServerFinalMessage(serverFinalMessage);
        });

        it(`errors when server iterations exceeed client maximum`, async () => {
            const client = new ScramRequestClient(algo, {
                maxIterations: 0x100, // This is way too low, never use this!
            });
            const server = new ScramRequestServer(algo, repo, saltGenerator, iterations);
            const clientFirstMessage = client.createClientFirstMessage(username);

            server.setClientFirstMessage(clientFirstMessage);
            const serverFirstmessage = await server.createServerFirstMessage();

            client.setServerFirstMessage(serverFirstmessage);
            chai.expect(client.getSaltedPassword(password)).to.be.rejectedWith(
                Error,
                `Iteration count of ${iterations} exceeed maximum of 256`
            );
        });

        it(`errors on invalid channel binding "y"`, async () => {
            const client = new ScramRequestClient(algo);
            const server = new ScramRequestServer(algo, repo, saltGenerator, iterations);
            const clientFirstMessage = new ScramMessageClientFirst("y,,n=user,r=T5BSEsIUvPg4V6+P8T57c9mhSbdA");

            client.setClientFirstMessage(clientFirstMessage);
            server.setClientFirstMessage(clientFirstMessage);
            const serverFirstMessage = await server.createServerFirstMessage();

            client.setServerFirstMessage(serverFirstMessage);
            const clientFinalMessage = await client.createClientFinalMessage(saltedPassword);

            server.setClientFinalMessage(clientFinalMessage);
            const serverFinalMessage = await server.createServerFinalMessage();

            chai.assert(serverFinalMessage.getError() === SCRAM_CHANNEL_BINDING_NOT_SUPPORTED);
        });

        it(`errors on invalid channel binding "p=invalid"`, async () => {
            const client = new ScramRequestClient(algo);
            const server = new ScramRequestServer(algo, repo, saltGenerator, iterations);
            const clientFirstMessage = new ScramMessageClientFirst("p=invalid,,n=user,r=T5BSEsIUvPg4V6+P8T57c9mhSbdA");

            client.setClientFirstMessage(clientFirstMessage);
            server.setClientFirstMessage(clientFirstMessage);
            const serverFirstMessage = await server.createServerFirstMessage();

            client.setServerFirstMessage(serverFirstMessage);
            const clientFinalMessage = await client.createClientFinalMessage(saltedPassword);

            server.setClientFinalMessage(clientFinalMessage);
            const serverFinalMessage = await server.createServerFinalMessage();

            chai.assert(serverFinalMessage.getError() === SCRAM_CHANNEL_BINDING_NOT_SUPPORTED);
        });
    });
});
