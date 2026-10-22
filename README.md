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
- 🚰 **Streaming** — `stream()` hands a body over as it arrives, with the same guard and pinning; an error document never reaches the sink.
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

Verbs: `get()`, `post()`, `post_json()`, `put()`, `delete()`, `head()`, or `request()` for anything else — and `stream()` for a body too big to hold.

### Streaming

For a body you pass on rather than keep — a file proxied to a browser, a member written into a zip:

```php
$response = $client->stream( $presigned_url, static function ( string $chunk ): void {
    echo $chunk;
    flush();
} );

if ( ! $response->ok ) {
    error_log( 'Stream failed: ' . $response->error );
}
```

The guard is the same as for every other verb: the target is validated, the connection is pinned to the address that was validated, and redirects are re-validated per hop. `fopen( $url )` cannot do the middle part — it checks nothing, and if you check first it connects to whatever DNS says the second time.

Only a **2xx** body reaches the sink. An error document or a redirect's body is kept on the `Response` (up to 64 KiB) instead of being written into somebody's download, so a sink that was never called means nothing went out, and you can still answer with an error of your own. Send your own headers from the first call of the sink, not before.

The timeout bounds connecting and any stall of that length; it does not bound the transfer, which takes as long as the file is big. `with_max_bytes()` still cuts it off mid-transfer.

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

### Redirects and credentials

A redirect that leaves the origin of the first request — another scheme, host or port — loses `Authorization`, `Proxy-Authorization` and `Cookie` for the rest of the chain. Any other header carrying a secret (an `X-Api-Key`, say) is not recognised as one, so don't combine it with `following_redirects()` towards a host you don't control.

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

`stream()` on a fake is answered from the same script as a `GET`, and a 2xx body is played into the sink in `Fake::CHUNK`-sized pieces; anything else comes back as scripted and the sink is never called.

A request is answered by the first matching route with uses left, then the next queued answer, then a bare `200`. `Fake::strict()` fails unscripted requests instead, so a test cannot pass on a call it never meant to make. The `with_*()` copies are clones, so a copy of a fake is still the fake and records into the same log.

## What the policy blocks

| | Examples |
|---|---|
| Loopback | `127.0.0.1`, `::1`, `localhost` |
| RFC 1918 | `10.x`, `172.16-31.x`, `192.168.x` |
| Link-local | `169.254.169.254` — cloud metadata |
| CGNAT | `100.64.0.0/10` |
| IPv6 private | `fd00::/8`, `fe80::/10` |
| IPv4-mapped | `::ffff:10.0.0.1` |
| IPv6 transition | NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo, SIIT `::ffff:0:0:0/96` |
| Special-purpose | documentation, benchmarking, multicast, `240.0.0.0/4`, site-local `fec0::/10` |
| Unplain hosts | `169%2e254%2e169%2e254`, `[fe80::1%25en0]`, raw Unicode — parsers disagree on them |
| Non-HTTP schemes | `file://`, `gopher://`, `dict://` |
| Credentials in URL | `http://real.com@internal/` |
| Non-HTTP ports | `:22`, `:3306`, `:6379`, `:11211` |

Three of those are worth calling out because they're routinely missed:

**Every resolved address must pass, not just the first.** A hostname answering with one public and one private address is a rebinding attempt, not a misconfiguration.

**NAT64 and 6to4 embed IPv4 inside IPv6.** `64:ff9b::a00:1` reaches `10.0.0.1`, and PHP's own filters consider it perfectly public.

**Validation alone is not enough.** DNS can answer differently between the check and the connection — that *is* DNS rebinding. The connection is pinned to the validated address via `CURLOPT_RESOLVE` — with an IPv6 address bracketed (`host:443:[2001:db8::1]`), the form curl documents. `SsrfResult::resolve_entry()` builds that entry, so anything else pinning a connection uses the same one rather than its own. Once connected, the address curl actually reached is compared with the pin and the request is abandoned before it is sent if they differ — the backstop for any URL curl reads differently from `parse_url()`. A guarded request never goes through a proxy (`http_proxy` and friends are ignored), because a proxy looks the name up again on its own side.

**Addresses are compared in canonical form.** `0064:ff9b::a9fe:a9fe` and `::ffff:a9fe:a9fe` are the metadata service spelled unusually; the check runs on the binary address, not the text.

## Testing

```bash
composer install
composer test
```

102 tests, run against a real PHP built-in server rather than a mocked transport — redirect handling, size caps, timeouts, streaming and pinning only exist at the transport layer, and a mock would just test the mock.

## License

GPL-2.0-or-later
