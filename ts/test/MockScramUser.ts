import { ScramUser } from "../user/ScramUser.js";

export class MockScramUser implements ScramUser {
    private readonly username;
    private readonly salt;
    private readonly iterations;
    private readonly storedKey;
    private readonly serverKey;

    constructor(username: string, salt: Uint8Array, iterations: number, storedKey: Uint8Array, serverKey: Uint8Array) {
        this.username = username;
        this.salt = salt;
        this.iterations = iterations;
        this.storedKey = storedKey;
        this.serverKey = serverKey;
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

    getStoredKey(): Uint8Array {
        return this.storedKey;
    }

    getServerKey(): Uint8Array {
        return this.serverKey;
    }
}
