export class ScramError extends Error {
    public readonly errorCode: string;

    constructor(errorCode: string, message?: string) {
        super(message || `SCRAM error: ${errorCode}`);
        this.errorCode = errorCode;
    }
}

export const SCRAM_INVALID_ENCODING = "invalid-encoding";
export const SCRAM_EXTENSIONS_NOT_SUPPORTED = "extensions-not-supported";
export const SCRAM_INVALID_PROOF = "invalid-proof";
export const SCRAM_CHANNEL_BINDINGS_DONT_MATCH = "channel-bindings-dont-match";
export const SCRAM_SERVER_DOES_SUPPORT_CHANNEL_BINDING = "server-does-support-channel-binding";
export const SCRAM_CHANNEL_BINDING_NOT_SUPPORTED = "channel-binding-not-supported";
export const SCRAM_UNSUPPORTED_CHANNEL_BINDING_TYPE = "unsupported-channel-binding-type";
export const SCRAM_UNKNOWN_USER = "unknown-user";
export const SCRAM_INVALID_USERNAME_ENCODING = "invalid-username-encoding";
export const SCRAM_NO_RESOURCES = "no-resources";
export const SCRAM_OTHER_ERROR = "other-error";
