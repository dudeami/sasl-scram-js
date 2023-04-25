import { Crypto } from "@peculiar/webcrypto";
import chai from "chai";
import chaiAsPromised from "chai-as-promised";
import { Base64 } from "js-base64";
import { ScramMessageClientFinal } from "../message/ScramMessageClientFinal.js";
import { ScramMessageClientFirst } from "../message/ScramMessageClientFirst.js";
import { ScramMessageServerFinal } from "../message/ScramMessageServerFinal.js";
import { ScramMessageServerFirst } from "../message/ScramMessageServerFirst.js";

chai.use(chaiAsPromised);

function getFuzz(length: number) {
    const array = new Uint8Array(length * 2);
    return new TextDecoder().decode(new Crypto().getRandomValues(array));
}

describe("SCRAM Message tests", () => {
    it(`parses a valid client-first-message`, () => {
        const messageTxt = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL";
        const message = new ScramMessageClientFirst(messageTxt);

        chai.assert(message.getMessage() == messageTxt);
        chai.assert(message.getUser() === "user");
        chai.assert(message.getNonce() === "fyko+d2lbbFgONRv9qkxdawL");
        chai.assert(message.getGS2CbindFlag() === "n");
    });

    it(`parses a valid server-first-message`, () => {
        const messageTxt = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
        const message = new ScramMessageServerFirst(messageTxt);

        chai.assert(message.getMessage() === messageTxt);
        chai.assert(message.getNonce() === "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j");
        chai.assert(Base64.fromUint8Array(message.getSalt()) === "QSXCR+Q6sek8bf92");
        chai.assert(message.getIterations() === 4096);
    });

    it(`parses a valid client-final-message`, () => {
        const messageTxt = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=";
        const message = new ScramMessageClientFinal(messageTxt);

        chai.assert(message.getMessage() === messageTxt);
        chai.assert(message.getGS2Header() === "biws");
        chai.assert(message.getNonce() === "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j");
        chai.assert(message.getClientProof() === "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
    });

    it(`parses a valid server-final-message with verifier`, () => {
        const messageTxt = "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";
        const message = new ScramMessageServerFinal(messageTxt);

        chai.assert(message.getMessage() === messageTxt);
        chai.assert(message.getVerifier() === "rmF9pqV8S7suAoZWja4dJRkFsKQ=");
    });

    it(`parses a valid server-final-message with error`, () => {
        const messageTxt = "e=invalid-proof";
        const message = new ScramMessageServerFinal(messageTxt);

        chai.assert(message.getMessage() === messageTxt);
        chai.assert(message.getError() === "invalid-proof");
    });

    it(`fails on invalid client-first-message`, () => {
        const messages = [getFuzz(32), "n,,n=user", `n,,n=${getFuzz(8)},r=${getFuzz(32)}`, `n,,r=${getFuzz(32)}`];
        for (const message of messages) {
            chai.expect(() => new ScramMessageClientFirst(message)).to.throw(Error);
        }
    });

    it(`fails on invalid server-first-message`, () => {
        const messages = [
            getFuzz(32),
            `r=${getFuzz(16)},s=3jPe,i=abcd`,
            `s=3jPe,i=4096`,
            `r=${getFuzz(16)},i=4096`,
            `r=${getFuzz(16)},s=3jPe`,
        ];
        for (const message of messages) {
            chai.expect(() => new ScramMessageServerFirst(message)).to.throw(
                Error,
                "Unable to read server-first-message"
            );
        }
    });

    it(`fails on invalid client-final-message`, () => {
        chai.expect(() => new ScramMessageClientFinal(getFuzz(32))).to.throw(
            Error,
            "Unable to read client-final-message"
        );
    });

    it(`fails on invalid server-final-message`, () => {
        chai.expect(() => new ScramMessageServerFinal(getFuzz(32))).to.throw(
            Error,
            "Unable to read server-final-message"
        );
    });

    it(`fails on invalid username failing SASLprep`, () => {
        chai.expect(() => new ScramMessageClientFirst("n,,n=username\u0007,r=fyko+d2lbbFgONRv9qkxdawL")).to.throw(
            Error,
            "Prohibited character, see https://tools.ietf.org/html/rfc4013#section-2.3"
        );
    });

    it(`reads username with characted mapped to nothing by SASLprep`, () => {
        const message = new ScramMessageClientFirst("n,,n=username\u00AD,r=fyko+d2lbbFgONRv9qkxdawL");
        chai.assert(message.getUser() === "username");
    });
});
