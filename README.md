# go-passwordless-sqlite

Inspired by `johnsto/go-passwordless`, see this [fork with SQLite support](https://github.com/mozey/go-passwordless). This repo might introduce backwards incompatible changes.

This library can be used for passwordless auth. That is done by sending a link that includes a secret token to the user. If the user can receive and click the link it proves ownership of e.g. an email address, social media account, or phone number


## Transports

Provides a means to transmit a token to the user

- *SMTPTransport* emails tokens via an SMTP server
- *LogTransport* prints tokens to stdout (for testing)


## Token Stores

A Token Store provides a mean to securely store and verify a token

- *SQLiteStore* stores encrypted tokens in an SQLite database

See repo linked above for 

- *MemStore* stores encrypted tokens in ephemeral memory.
- *CookieStore* stores tokens in encrypted session cookies. Mandates that the user signs in on the same device that they generated the sign in request from
- *RedisStore* stores encrypted tokens in a Redis instance


## Example 

Run the example to see how this lib can be used to implement the UI

```go
go run ./example/...

```