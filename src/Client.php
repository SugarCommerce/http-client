<?php
/**
 * SSRF-guarded outbound HTTP client.
 *
 * @package   SugarCommerce\HttpClient
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\HttpClient;

/**
 * Class Client
 *
 * One place for curl, with the SSRF policy on by default.
 *
 * Every HTTP library will happily fetch `http://169.254.169.254/` for
 * you. That address returns cloud instance credentials, and reaching it
 * only requires a URL field somewhere in your admin. Guzzle does not
 * guard against this; neither does `file_get_contents`. Here it is the
 * default, and turning it off is explicit:
 *
 *   $client = new Client();                       // guarded
 *   $client = new Client( ssrf: null );           // not guarded
 *   $client = $client->without_ssrf();            // not guarded, per-call
 *
 * Never throws for transport problems — see {@see Response}.
 *
 * Typical use:
 *
 *   $response = ( new Client() )->get( $url );
 *
 *   if ( $response->ok ) {
 *       $data = $response->json();
 *   }
 *
 * @since 1.0.0
 */
readonly class Client {

	/**
	 * Protocols curl may speak, for the request and any redirect.
	 */
	private const PROTOCOLS = CURLPROTO_HTTP | CURLPROTO_HTTPS;

	/**
	 * @since 1.0.0
	 *
	 * @param int                   $timeout         Seconds, connect and total.
	 * @param int                   $max_redirects   Redirects to follow. Each
	 *                                               hop is re-validated
	 *                                               against the policy, which
	 *                                               is why curl's own
	 *                                               `FOLLOWLOCATION` is not
	 *                                               used.
	 * @param int                   $max_bytes       Abort once the body
	 *                                               exceeds this. 0 disables.
	 * @param string                $user_agent      `User-Agent` header.
	 * @param SsrfPolicy|null       $ssrf            Policy, or null to
	 *                                               disable the guard.
	 * @param array<string, string> $default_headers Sent with every request.
	 */
	public function __construct(
		public int $timeout = 10,
		public int $max_redirects = 0,
		public int $max_bytes = 0,
		public string $user_agent = 'sugarcommerce-http-client/1.0',
		public ?SsrfPolicy $ssrf = new SsrfPolicy(),
		public array $default_headers = array(),
	) {}

	/* ─── Configuration ─────────────────────────────────────────────── */

	/**
	 * A copy with a different timeout.
	 *
	 * @since 1.0.0
	 *
	 * @param int $seconds Timeout.
	 *
	 * @return self
	 */
	public function with_timeout( int $seconds ): self {
		return new self( $seconds, $this->max_redirects, $this->max_bytes, $this->user_agent, $this->ssrf, $this->default_headers );
	}

	/**
	 * A copy that follows redirects.
	 *
	 * @since 1.0.0
	 *
	 * @param int $max Hops to follow.
	 *
	 * @return self
	 */
	public function following_redirects( int $max = 3 ): self {
		return new self( $this->timeout, $max, $this->max_bytes, $this->user_agent, $this->ssrf, $this->default_headers );
	}

	/**
	 * A copy that refuses bodies over a size.
	 *
	 * @since 1.0.0
	 *
	 * @param int $bytes Cap.
	 *
	 * @return self
	 */
	public function with_max_bytes( int $bytes ): self {
		return new self( $this->timeout, $this->max_redirects, $bytes, $this->user_agent, $this->ssrf, $this->default_headers );
	}

	/**
	 * A copy with extra default headers.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, string> $headers Merged over the existing set.
	 *
	 * @return self
	 */
	public function with_headers( array $headers ): self {
		return new self( $this->timeout, $this->max_redirects, $this->max_bytes, $this->user_agent, $this->ssrf, $headers + $this->default_headers );
	}

	/**
	 * A copy with the SSRF guard removed.
	 *
	 * Only for a fixed endpoint you control — an API base URL from your
	 * own configuration. Never for a URL that reached you from a form,
	 * an API request, or a database row someone else can write to.
	 *
	 * @since 1.0.0
	 *
	 * @return self
	 */
	public function without_ssrf(): self {
		return new self( $this->timeout, $this->max_redirects, $this->max_bytes, $this->user_agent, null, $this->default_headers );
	}

	/**
	 * A copy using a different policy.
	 *
	 * @since 1.0.0
	 *
	 * @param SsrfPolicy $policy Replacement policy.
	 *
	 * @return self
	 */
	public function with_ssrf_policy( SsrfPolicy $policy ): self {
		return new self( $this->timeout, $this->max_redirects, $this->max_bytes, $this->user_agent, $policy, $this->default_headers );
	}

	/* ─── Verbs ─────────────────────────────────────────────────────── */

	/**
	 * GET a URL.
	 *
	 * @since 1.0.0
	 *
	 * @param string                $url     URL.
	 * @param array<string, string> $headers Extra headers.
	 *
	 * @return Response
	 */
	public function get( string $url, array $headers = array() ): Response {
		return $this->request( 'GET', $url, null, $headers );
	}

	/**
	 * POST a raw body.
	 *
	 * @since 1.0.0
	 *
	 * @param string                $url     URL.
	 * @param string                $body    Already-encoded body.
	 * @param array<string, string> $headers Extra headers.
	 *
	 * @return Response
	 */
	public function post( string $url, string $body, array $headers = array() ): Response {
		return $this->request( 'POST', $url, $body, $headers );
	}

	/**
	 * POST a JSON body.
	 *
	 * @since 1.0.0
	 *
	 * @param string                $url     URL.
	 * @param mixed                 $data    Anything json_encode accepts.
	 * @param array<string, string> $headers Extra headers.
	 *
	 * @return Response
	 */
	public function post_json( string $url, mixed $data, array $headers = array() ): Response {
		return $this->request(
			'POST',
			$url,
			json_encode( $data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ?: '',
			array( 'Content-Type' => 'application/json' ) + $headers
		);
	}

	/**
	 * PUT a raw body.
	 *
	 * @since 1.0.0
	 *
	 * @param string                $url     URL.
	 * @param string                $body    Body.
	 * @param array<string, string> $headers Extra headers.
	 *
	 * @return Response
	 */
	public function put( string $url, string $body, array $headers = array() ): Response {
		return $this->request( 'PUT', $url, $body, $headers );
	}

	/**
	 * DELETE a URL.
	 *
	 * @since 1.0.0
	 *
	 * @param string                $url     URL.
	 * @param array<string, string> $headers Extra headers.
	 *
	 * @return Response
	 */
	public function delete( string $url, array $headers = array() ): Response {
		return $this->request( 'DELETE', $url, null, $headers );
	}

	/**
	 * HEAD a URL.
	 *
	 * @since 1.0.0
	 *
	 * @param string                $url     URL.
	 * @param array<string, string> $headers Extra headers.
	 *
	 * @return Response
	 */
	public function head( string $url, array $headers = array() ): Response {
		return $this->request( 'HEAD', $url, null, $headers );
	}

	/* ─── Engine ────────────────────────────────────────────────────── */

	/**
	 * Perform a request.
	 *
	 * Redirects are followed by hand rather than by curl, so the policy
	 * runs against every hop. `FOLLOWLOCATION` would validate the first
	 * URL and then follow a `302` to `127.0.0.1` without another word.
	 *
	 * @since 1.0.0
	 *
	 * @param string                $method  HTTP verb.
	 * @param string                $url     URL.
	 * @param string|null           $body    Request body.
	 * @param array<string, string> $headers Extra headers.
	 *
	 * @return Response
	 */
	public function request( string $method, string $url, ?string $body = null, array $headers = array() ): Response {
		$method  = strtoupper( $method );
		$current = $url;
		$started = microtime( true );

		for ( $hop = 0; $hop <= $this->max_redirects; $hop++ ) {
			$pinned = null;

			if ( null !== $this->ssrf ) {
				$check = $this->ssrf->validate( $current );

				if ( ! $check->ok ) {
					return Response::failure( 'blocked: ' . $check->error );
				}

				$pinned = $check;
			}

			$result = $this->execute( $method, $current, $body, $headers, $pinned );

			$is_redirect = $result['status'] >= 300 && $result['status'] < 400 && '' !== $result['location'];

			if ( $is_redirect && $this->max_redirects > 0 ) {
				// Following was requested but the budget is spent. Report
				// that, rather than handing back a 3xx the caller asked us
				// to resolve — silently returning it looks like the remote
				// end simply answered 302.
				if ( $hop >= $this->max_redirects ) {
					return Response::failure( 'too many redirects', $result['status'] );
				}

				$current = $result['location'];

				// Only the first request carries a body; a 303, and in
				// practice a 301/302 too, becomes a GET.
				if ( in_array( $result['status'], array( 301, 302, 303 ), true ) ) {
					$method = 'HEAD' === $method ? 'HEAD' : 'GET';
					$body   = null;
				}

				continue;
			}

			// max_redirects === 0 means "do not follow", so a 3xx is a
			// legitimate response to hand back, exactly as curl behaves
			// with FOLLOWLOCATION off.

			$duration = microtime( true ) - $started;

			if ( false === $result['body'] || 0 === $result['status'] ) {
				return new Response(
					false,
					$result['status'],
					error: '' !== $result['error'] ? $result['error'] : 'request failed',
					duration: $duration,
					final_url: $current
				);
			}

			$response_body = (string) $result['body'];

			if ( $this->max_bytes > 0 && strlen( $response_body ) > $this->max_bytes ) {
				return new Response( false, $result['status'], error: 'response exceeds size limit', duration: $duration, final_url: $current );
			}

			$ok = $result['status'] >= 200 && $result['status'] < 300;

			return new Response(
				$ok,
				$result['status'],
				$response_body,
				$result['content_type'],
				$ok ? '' : 'HTTP ' . $result['status'],
				$result['headers'],
				$duration,
				$current
			);
		}

		return Response::failure( 'too many redirects' );
	}

	/**
	 * Issue one request, following nothing.
	 *
	 * @since 1.0.0
	 *
	 * @param string                $method  Verb.
	 * @param string                $url     URL.
	 * @param string|null           $body    Body.
	 * @param array<string, string> $headers Extra headers.
	 * @param SsrfResult|null       $pinned  Validated target, when guarded.
	 *
	 * @return array{status:int, body:string|false, content_type:string, error:string, location:string, headers:array<string,string>}
	 */
	private function execute( string $method, string $url, ?string $body, array $headers, ?SsrfResult $pinned ): array {
		$handle          = curl_init( $url );
		$response_headers = array();

		$options = array(
			CURLOPT_CUSTOMREQUEST   => $method,
			CURLOPT_RETURNTRANSFER  => true,
			CURLOPT_FOLLOWLOCATION  => false,
			CURLOPT_TIMEOUT         => $this->timeout,
			CURLOPT_CONNECTTIMEOUT  => $this->timeout,
			CURLOPT_USERAGENT       => $this->user_agent,
			CURLOPT_PROTOCOLS       => self::PROTOCOLS,
			CURLOPT_REDIR_PROTOCOLS => self::PROTOCOLS,
			CURLOPT_NOBODY          => 'HEAD' === $method,
			CURLOPT_HEADERFUNCTION  => static function ( $handle, string $line ) use ( &$response_headers ): int {
				$parts = explode( ':', $line, 2 );

				if ( 2 === count( $parts ) ) {
					$response_headers[ strtolower( trim( $parts[0] ) ) ] = trim( $parts[1] );
				}

				return strlen( $line );
			},
		);

		$merged = $headers + $this->default_headers;

		if ( array() !== $merged ) {
			$options[ CURLOPT_HTTPHEADER ] = self::normalize_headers( $merged );
		}

		if ( null !== $body && '' !== $body ) {
			$options[ CURLOPT_POSTFIELDS ] = $body;
		}

		if ( null !== $pinned ) {
			// Pin the connection to the address the policy validated, so
			// a second DNS answer cannot redirect us somewhere private.
			$options[ CURLOPT_RESOLVE ] = array( $pinned->resolve_entry() );
		}

		if ( $this->max_bytes > 0 ) {
			// Abort mid-transfer rather than buffering an oversized body
			// and checking its length afterwards.
			$options[ CURLOPT_NOPROGRESS ]       = false;
			$options[ CURLOPT_PROGRESSFUNCTION ] = fn( $handle, int $download_total, int $downloaded ): int
				=> ( $downloaded > $this->max_bytes || $download_total > $this->max_bytes ) ? 1 : 0;
		}

		curl_setopt_array( $handle, $options );

		$result = curl_exec( $handle );
		$out    = array(
			'status'       => (int) curl_getinfo( $handle, CURLINFO_HTTP_CODE ),
			'body'         => is_string( $result ) ? $result : false,
			'content_type' => strtok( (string) curl_getinfo( $handle, CURLINFO_CONTENT_TYPE ), ';' ) ?: '',
			'error'        => curl_error( $handle ),
			'location'     => (string) curl_getinfo( $handle, CURLINFO_REDIRECT_URL ),
			'headers'      => $response_headers,
		);

		unset( $handle );

		return $out;
	}

	/**
	 * Convert headers to curl's `Name: value` list.
	 *
	 * Accepts an associative map or an already-formatted list. Values
	 * containing line breaks are rejected — that is header injection,
	 * not a formatting quirk.
	 *
	 * @since 1.0.0
	 *
	 * @param array<int|string, string> $headers Headers.
	 *
	 * @return string[]
	 *
	 * @throws \InvalidArgumentException On a header containing CR or LF.
	 */
	public static function normalize_headers( array $headers ): array {
		$out = array();

		foreach ( $headers as $name => $value ) {
			$line = is_int( $name ) ? (string) $value : $name . ': ' . $value;

			if ( 1 === preg_match( '/[\r\n\x00]/', $line ) ) {
				throw new \InvalidArgumentException( 'Header contains a line break: ' . var_export( $name, true ) );
			}

			$out[] = $line;
		}

		return $out;
	}
}
