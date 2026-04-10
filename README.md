# Dependency free OTP implementation

Simple and dependency free OTP implementation (HOTP, TOTP) for Node.js written in TypeScript. Passes RFC test vectors and works with common authenticator apps.

## Features

- HOTP
- TOTP (builds on top of HOTP)
- `otpauth://` URL generation

Generating QR codes for `otpauth://` URLs is **not** within the scope of this library. There are [plenty of good QR code libraries](https://www.npmjs.com/search?q=qr) out there. Just run your URL through one of them and you're good to go. There's an example QR code that works in conjunction with the example code below if you want to test it with your own authenticator app, though.

## Installation

```bash
npm install @punikonta/node-otp
```

## Example

Example usage for TOTP in plain JavaScript:

```javascript
import Otp from '@punikonta/node-otp'

// example 128 bit secret for demonstration only! don't use this in your application.
// this must be random, stored securely and be unique for each user.
const secret = Buffer.from('8eddb53e05fa936c2530c8045a58f81b', 'hex')

// options are optional. these are the defaults and common practice.
// just omit the options parameter if you're fine with the defaults.
const options = {
    algorithm: Otp.HashAlgorithm.SHA1,
    digits: 6,
    period: 30,
}

// default value. omit if you just want to use the current time.
const now = Date.now()

const token = Otp.Totp.generate(secret, now, options)
const remaining = Otp.Totp.remaining(options.period, now)
const url = Otp.Url.getTotpUrl('example.com', 'foobar', secret, options)

// default value. omit if you're fine with the default.
const window = 1
const valid = Otp.Totp.validate('123456', secret, now, window, options)

console.log(`token: ${token}`)
console.log(`valid for ${remaining.toFixed(2)} seconds`)
console.log(url)
console.log(`is 123456 valid? ${valid ? 'yes' : 'no'}`)
```

If you want to verify the example right away with an authenticator app, you can use the following QR code without having to generate one yourself:

![example QR code](assets/example.png)

`otpauth://totp/example.com:foobar?secret=R3O3KPQF7KJWYJJQZACFUWHYDM&algorithm=SHA1&digits=6&period=30&issuer=example.com`

## Motivation

I wanted a project with a small scope to get my hands dirty with TypeScript and NPM packaging. Also I've been looking for a TOTP library at the same time. I couldn't find one that I liked, so I decided to create my own. TOTP builds on top of HOTP, so I implemented that as well.

## Remarks

I've successfully tested the TOTP functionality with the following authenticator apps:

- Authy
- Google Authenticator
- Microsoft Authenticator
- Proton Authenticator
- Bitwarden Authenticator

Double check if you want to use anything but `SHA1` as your hash algorithm. Some popular authenticator apps don't support anything else and even go as far as completely ignoring that parameter, silently giving the user wrong tokens. To catch this and other issues early, your onboarding flow should implement a successful token readback while setting up 2FA anyway.

Also don't use a `window` value other than `0` for HOTP unless you know what you're doing. Managing the HOTP counter is up to you.

The default `window` value of `1` for TOTP generally is fine and common practice to mitigate small clock drifts between the server and the user.

Don't use the `Base32` class as a generic base32 encoder/decoder. Its behavior is tailored to the needs of this library and may not be suitable for other purposes than OTP secrets in URLs, mainly because it strips and ignores padding. See [Google Authenticator's Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format#secret).

## API

The API uses the following types and enums:

```typescript
enum HashAlgorithm {
    SHA1 = 'sha1',
    SHA256 = 'sha256',
    SHA384 = 'sha384',
    SHA512 = 'sha512',
}

type HotpOptions = {
    algorithm: HashAlgorithm
    digits: number
}

type TotpOptions = {
    algorithm: HashAlgorithm
    digits: number
    period: number
}
```

### HOTP

```typescript
Hotp.generate(
    secret: Buffer,
    counter: number,
    options?: Partial<HotpOptions>
): string

Hotp.validate(
    token: string,
    secret: Buffer,
    counter: number,
    window: number = 0,
    options?: Partial<HotpOptions>
): boolean

// default values for option parameters that are omitted
static readonly DEFAULTS: HotpOptions = {
    algorithm: HashAlgorithm.SHA1,
    digits: 6,
}
```

### TOTP

```typescript
Totp.generate(
    secret: Buffer,
    time: number = Date.now(),
    options?: Partial<TotpOptions>
): string

Totp.validate(
    token: string,
    secret: Buffer,
    time: number = Date.now(),
    window: number = 1,
    options?: Partial<TotpOptions>
): boolean

// remaining time until next token (seconds, fractional)
Totp.remaining(
    period: number = 30,
    time: number = Date.now()
): number

// default values for option parameters that are omitted
static readonly DEFAULTS: TotpOptions = {
    algorithm: HashAlgorithm.SHA1,
    digits: 6,
    period: 30,
}
```

### URL

```typescript
// HOTP
Url.getHotpUrl(
    issuer: string, // usually a domain or application name
    label: string, // usually the username or email of the user
    secret: Buffer,
    counter: number,
    options?: Partial<HotpOptions>
): string

// TOTP
Url.getTotpUrl(
    issuer: string, // usually a domain or application name
    label: string, // usually the username or email of the user
    secret: Buffer,
    options?: Partial<TotpOptions>
): string
```

## TODO

Probably a good idea to add some sanity checks in the future, e.g. for nonsensical stuff like negative periods, windows or missing mandatory parameters.