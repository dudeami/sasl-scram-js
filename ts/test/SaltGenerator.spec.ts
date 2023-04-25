import { assert } from "chai";
import { Base64 } from "js-base64";
import { ScramSha256 } from "../algo/ScramSha256.js";
import { PepperedSaltGenerator, RandomSaltGenerator } from "../utils/SaltGenerator.js";

describe(`SaltGenerator tests`, () => {
    it(`Uses a PepperedSaltGenerator to generate deterministic passwords`, async () => {
        const generator = new PepperedSaltGenerator(ScramSha256, "some-pepper");

        const username_1 = Base64.fromUint8Array(await generator.get("username"));
        const username_2 = Base64.fromUint8Array(await generator.get("username"));
        assert(username_1 === username_2);
        const someone = Base64.fromUint8Array(await generator.get("someone"));
        assert(username_1 !== someone);
    });

    it(`Users a RandomSaltGenerator to create random salts`, async () => {
        const generator = new RandomSaltGenerator(ScramSha256, 24);

        const username_1 = Base64.fromUint8Array(await generator.get("username"));
        const username_2 = Base64.fromUint8Array(await generator.get("username"));
        assert(username_1 !== username_2);
        const someone_1 = Base64.fromUint8Array(await generator.get("someone"));
        const someone_2 = Base64.fromUint8Array(await generator.get("someone"));
        assert(someone_1 !== username_1);
        assert(someone_2 !== username_2);
    });
});
