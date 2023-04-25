import { ScramUser } from "./ScramUser.js";

/**
 * Represents a user repository that allows lookup by a unique identifier for a user.
 */
export interface ScramUserRepo {
    /**
     * Finds a user within the repository, or returns `false`
     * @param username The unique identifier for the user.
     * @returns A `ScramUser`, or `false`
     */
    find(username: string): ScramUser;

    /**
     * Returns true if the user with the given name exists, otherwise false
     * @param username The unique identifier for the user.
     * @returns A boolean indicating if the user exists or not
     */
    has(username: string): boolean;
}
