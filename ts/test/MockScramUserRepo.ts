import { ScramUserRepo } from "../user/ScramUserRepo.js";
import { SaltGenerator } from "../utils/SaltGenerator.js";
import { SCRAM_UNKNOWN_USER, ScramError } from "../utils/ScramError.js";
import { MockScramUser } from "./MockScramUser.js";

export class MockScramUserRepo implements ScramUserRepo {
    private users: { [name: string]: MockScramUser } = {};
    private readonly saltGenerator;

    constructor(saltGenerator: SaltGenerator) {
        this.saltGenerator = saltGenerator;
    }

    async addUser(user: MockScramUser) {
        this.users[user.getUsername()] = user;
    }

    find(username: string): MockScramUser {
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
