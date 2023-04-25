/**
 * Simple parser for SCRAM param strings, returns a dictonary of the named parameters. For example, a
 * client-first-message with the structure of:
 *
 * n,,n=user,r=JGJSURiTWKnNivjGf6Wz2vn7dcHvuP0U
 *
 * would return the following dictonary:
 *
 * {
 *     "n": "user",
 *     "r": "JGJSURiTWKnNivjGf6Wz2vn7dcHvuP0U"
 * }
 *
 * Note that the first "n" will create an empty key in the dictonary, but is overridden by the user "n" param.
 * Implementations should remove the GS2 header of client-first-message before reading the param string.
 *
 * @param str SCRAM message
 * @returns Dictonary of named parameters
 */
export function readScramParamString(str: string) {
    const parts = str.split(",");

    const results: { [name: string]: string } = {};
    for (const part of parts) {
        const index = part.indexOf("=");
        if (index !== -1) {
            const left = part.substring(0, index).trim();
            const right = part.substring(index + 1).trim();
            results[left] = right;
        }
    }
    return results;
}
