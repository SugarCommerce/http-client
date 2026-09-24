# HTTP Client

Outbound HTTP with SSRF protection on by default. Validates the target, pins the connection to the address it validated, re-validates every redirect hop, and caps response size. Zero dependencies.

## Why

Every HTTP library will happily fetch `http://169.254.169.254/` for you. On AWS, GCP and Azure that returns instance credentials. Reaching it needs nothing more than a URL field somewhere in your admin — a webhook endpoint, an "import from URL" box, an avatar someone pasted.

Guzzle doesn't guard against this. Neither does `file_get_contents`. Here it's the default, and disabling it is explicit.

## Features

- 🛡️ **SSRF guarded by default** — private, loopback, link-local, CGNAT and reserved ranges blocked, IPv4 and IPv6.
- 📌 **Connection pinning** — connects to the address that was validated, closing the DNS-rebinding window between check and connect.
- 🔀 **Per-hop redirect validation** — every hop goes back through the policy, which `CURLOPT_FOLLOWLOCATION` cannot do.
- 🔌 **Port allowlist** — a public IP on `:6379` is still somebody's Redis.
- 📏 **Size caps** — aborts mid-transfer instead of buffering an oversized body.
- 🚫 **Never throws for transport errors** — a refused connection is a normal outcome, not an exception.
- 🧾 **Typed response** — `ok`, `status`, `json()`, `header()`, and error-class predicates.

## Requirements

PHP 8.5+, `ext-curl`

## Installation

```bash
composer require sugarcommerce/http-client
```

## Usage

```php
use SugarCommerce\HttpClient\Client;

$client   = new Client();
$response = $client->get( 'https://api.example.com/things' );

if ( $response->ok ) {
    $data = $response->json();
}
```

Verbs: `get()`, `post()`, `post_json()`, `put()`, `delete()`, `head()`, or `request()` for anything else.

### Responses

Never throws. Check the result:

```php
$response->ok                 // 2xx
$response->failed()
$response->status
$response->body
$response->json()             // null if absent or invalid
$response->header( 'etag' )
$response->duration           // seconds
$response->final_url          // after redirects

$response->client_error()     // 4xx — don't retry
$response->server_error()     // 5xx — worth retrying
$response->transport_error()  // never reached the remote end at all
```

That last distinction is the one worth having: a 500 deserves a retry, a 404 doesn't, and a blocked URL is neither.

### Configuration

Immutable — each helper returns a new client:

```php
$client = ( new Client() )
    ->with_timeout( 30 )
    ->following_redirects( 3 )
    ->with_max_bytes( 5 * 1024 * 1024 )
    ->with_headers( [ 'Authorization' => 'Bearer …' ] );
```

### Turning the guard off

Only for a fixed endpoint you control — an API base URL from your own configuration. Never for a URL that arrived from a form, an API request, or a database row someone else can write to:

```php
$client = new Client( ssrf: null );
$client = ( new Client() )->without_ssrf();
```

### Tuning the policy

```php
use SugarCommerce\HttpClient\SsrfPolicy;

new SsrfPolicy( allowed_ports: [ 80, 443, 8080 ] );
SsrfPolicy::permissive();   // private addresses + any port — dev and tests only
```

### Faking it in tests

`Fake` extends `Client`, so anything that takes a client takes it. It never touches the network and records every request.

```php
use SugarCommerce\HttpClient\{Fake, Response};

$http = ( new Fake() )
    ->on( 'GET', 'https://api.example.com/things/*', new Response( true, 200, '{"id":1}' ) )
    ->on( 'POST', '*', Response::failure( 'timeout' ), times: 2 )   // an outage, then…
    ->queue( new Response( true, 201 ) );                            // …the next unrouted answer

$http->sent( 'POST', 'https://api.example.com/*' );  // [ [method, url, body, headers], … ]
$http->methods();                                    // [ 'GET', 'POST', … ]
```

A request is answered by the first matching route with uses left, then the next queued answer, then a bare `200`. `Fake::strict()` fails unscripted requests instead, so a test cannot pass on a call it never meant to make. The `with_*()` copies return the fake itself rather than a real client.

## What the policy blocks

| | Examples |
|---|---|
| Loopback | `127.0.0.1`, `::1`, `localhost` |
| RFC 1918 | `10.x`, `172.16-31.x`, `192.168.x` |
| Link-local | `169.254.169.254` — cloud metadata |
| CGNAT | `100.64.0.0/10` |
| IPv6 private | `fd00::/8`, `fe80::/10` |
| IPv4-mapped | `::ffff:10.0.0.1` |
| IPv6 transition | NAT64 `64:ff9b::/96`, 6to4 `2002::/16` |
| Non-HTTP schemes | `file://`, `gopher://`, `dict://` |
| Credentials in URL | `http://real.com@internal/` |
| Non-HTTP ports | `:22`, `:3306`, `:6379`, `:11211` |

Three of those are worth calling out because they're routinely missed:

**Every resolved address must pass, not just the first.** A hostname answering with one public and one private address is a rebinding attempt, not a misconfiguration.

**NAT64 and 6to4 embed IPv4 inside IPv6.** `64:ff9b::a00:1` reaches `10.0.0.1`, and PHP's own filters consider it perfectly public.

**Validation alone is not enough.** DNS can answer differently between the check and the connection — that *is* DNS rebinding. The connection is pinned to the validated address via `CURLOPT_RESOLVE`.

## Testing

```bash
composer install
composer test
```

78 tests, run against a real PHP built-in server rather than a mocked transport — redirect handling, size caps, timeouts and pinning only exist at the transport layer, and a mock would just test the mock.

## License

GPL-2.0-or-later
