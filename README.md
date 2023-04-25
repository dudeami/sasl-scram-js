# Salted Challenge Response Authentication Mechanism (SCRAM) for JavaScript environments

This package aims to bring SCRAM to javascript environments, namely Node.JS and standard web browsers.

## Preface

**This package has not been audited!** This package may not provide the same level of security as the SCRAM
specification indicates.

This package is not currently intended for production, and needs more development/testing to make sure it properly meets
the RFC standards. Currently, it has not been tested on servers other than the one provided in this package. There might
be minor differences in implementation that lead to invalid authentication requests. It is being released at the moment
to gather feedback.

This package was made to utilize the security benefits of SCRAM authentication in javascript environments, including
standard web browsers. Channel-binding is currently not implemented as most javascript environments do not have access
to the required certificate data to implement the feature. Benefits of using SCRAM over sending plain or hashed
passwords are still numerous:

-   No MITM access to cleartext passwords
-   Database leak will not provide sufficent data to create valid authentication requests
-   Authentication requests cannot be replayed

Overall, liability is minimized handling a users password. For more information on security implications, please visit
[RFC 5802 Section 9][1].

## Compatability

To ensure maximum compatability, this package uses the `@peculiar/webcrypto` to ensure access to the `Crypto` object
across environments. While most modern web browsers have access to this API by default, Node.JS has only moved the
`Crypto` api status to stable in v20.0.0. This may eventually change once support and widespread use of Node v20.0.0
negates any benefits from using the `@peculiar/webcrypto` package.

## Example usage

As implementing SCRAM is not exactly a small script, the [ts/example.ts][2] file is provided with a simple
implementation that attempts to closely resemble a production implementation. In the future other implementation
examples will be provided as they become available.

[1]: https://datatracker.ietf.org/doc/html/rfc5802#section-9
[2]: ts/example.ts
