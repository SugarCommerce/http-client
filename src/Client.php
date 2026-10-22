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
	private const int PROTOCOLS = CURLPROTO_HTTP | CURLPROTO_HTTPS;

	/**
	 * Most of a non-2xx body stream() keeps, for saying what went wrong.
	 */
	private const int KEPT = 65536;

	/**
	 * Request headers that carry credentials, lowercase.
	 *
	 * Dropped from a request the moment a redirect leaves the origin it was
	 * sent to, so an API token meant for one host is never handed to a host
	 * that host pointed at.
	 */
	private const array CREDENTIALS = array( 'authorization', 'proxy-authorization', 'cookie' );

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

	// Every copy below is a clone with one property changed, not a new
	// instance: `new self` from a subclass builds the parent, so a test double
	// asked for a copy with a shorter timeout quietly became the real client
	// and sent real requests. A clone is whatever it was cloned from.

	/**
	 * A copy with a different timeout.
	 *
	 * @since 1.0.0
	 *
	 * @param int $seconds Timeout.
	 *
	 * @return static
	 */
	public function with_timeout( int $seconds ): static {
		return clone( $this, array( 'timeout' => $seconds ) );
	}

	/**
	 * A copy that follows redirects.
	 *
	 * @since 1.0.0
	 *
	 * @param int $max Hops to follow.
	 *
	 * @return static
	 */
	public function following_redirects( int $max = 3 ): static {
		return clone( $this, array( 'max_redirects' => $max ) );
	}

	/**
	 * A copy that refuses bodies over a size.
	 *
	 * @since 1.0.0
	 *
	 * @param int $bytes Cap.
	 *
	 * @return static
	 */
	public function with_max_bytes( int $bytes ): static {
		return clone( $this, array( 'max_bytes' => $bytes ) );
	}

	/**
	 * A copy with extra default headers.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, string> $headers Merged over the existing set.
	 *
	 * @return static
	 */
	public function with_headers( array $headers ): static {
		return clone( $this, array( 'default_headers' => $headers + $this->default_headers ) );
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
	 * @return static
	 */
	public function without_ssrf(): static {
		return clone( $this, array( 'ssrf' => null ) );
	}

	/**
	 * A copy using a different policy.
	 *
	 * @since 1.0.0
	 *
	 * @param SsrfPolicy $policy Replacement policy.
	 *
	 * @return static
	 */
	public function with_ssrf_policy( SsrfPolicy $policy ): static {
		return clone( $this, array( 'ssrf' => $policy ) );
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
	 *
	 * @throws \InvalidArgumentException On a header containing CR, LF or NUL.
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
	 *
	 * @throws \InvalidArgumentException On a header containing CR, LF or NUL.
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
	 *
	 * @throws \InvalidArgumentException On a header containing CR, LF or NUL.
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
	 *
	 * @throws \InvalidArgumentException On a header containing CR, LF or NUL.
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
	 *
	 * @throws \InvalidArgumentException On a header containing CR, LF or NUL.
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
	 *
	 * @throws \InvalidArgumentException On a header containing CR, LF or NUL.
	 */
	public function head( string $url, array $headers = array() ): Response {
		return $this->request( 'HEAD', $url, null, $headers );
	}

	/**
	 * GET a URL and hand its body over as it arrives, instead of keeping it.
	 *
	 * For bodies too big to hold — a file being passed through to a browser,
	 * a member being written into an archive. The same guard as every other
	 * verb: the target is validated, the connection is pinned to the address
	 * that was validated, and each redirect hop goes back through the policy.
	 * Opening the URL with fopen() instead would check one DNS answer and
	 * then connect to whatever the next one says.
	 *
	 * Only a 2xx body reaches the sink. An error document, or the body of a
	 * redirect, is never written into somebody's download; up to 64 KiB of
	 * it is kept on the Response instead, for the log. So a sink that has not
	 * been called by the time this returns means nothing was passed on —
	 * which is the moment a caller can still answer with an error of its own.
	 *
	 * The timeout bounds connecting, and any stretch that long with no bytes
	 * at all; it does not bound the transfer, which takes as long as the file
	 * is big. The size cap, when set, still aborts mid-transfer.
	 *
	 * @since 1.4.0
	 *
	 * @param string                $url     URL.
	 * @param \Closure              $sink    Called with each chunk of a 2xx body,
	 *                                       in order: `function ( string $chunk ): void`.
	 * @param array<string, string> $headers Extra headers, e.g. a Range.
	 *
	 * @return Response Status and headers. The body is empty when it went to
	 *                  the sink. `ok` is false when the transfer failed,
	 *                  including partway through — by then the sink has had
	 *                  some of the bytes, and the caller decides what a
	 *                  partial body means.
	 *
	 * @throws \InvalidArgumentException On a header containing CR, LF or NUL.
	 */
	public function stream( string $url, \Closure $sink, array $headers = array() ): Response {
		return $this->send( 'GET', $url, null, $headers, $sink );
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
	 *
	 * @throws \InvalidArgumentException On a verb that is not an HTTP token,
	 *                                   or a header containing CR, LF or NUL.
	 */
	public function request( string $method, string $url, ?string $body = null, array $headers = array() ): Response {
		return $this->send( $method, $url, $body, $headers, null );
	}

	/**
	 * Perform a request, keeping the body or handing it to a sink.
	 *
	 * A hop that leaves the origin of the first request — another scheme,
	 * host or port — loses the `Authorization`, `Proxy-Authorization` and
	 * `Cookie` headers, for the rest of the chain. The headers were meant
	 * for the first host; the next one is wherever that host said to go.
	 *
	 * @since 1.4.0
	 * @since 1.5.0 Drops credential headers on a cross-origin redirect.
	 *
	 * @param string                $method  HTTP verb.
	 * @param string                $url     URL.
	 * @param string|null           $body    Request body.
	 * @param array<string, string> $headers Extra headers.
	 * @param \Closure|null         $sink    Receives a 2xx body as it arrives,
	 *                                       or null to keep it.
	 *
	 * @return Response
	 *
	 * @throws \InvalidArgumentException On a verb that is not an HTTP token,
	 *                                   or a header containing CR, LF or NUL.
	 */
	private function send( string $method, string $url, ?string $body, array $headers, ?\Closure $sink ): Response {
		$method  = strtoupper( $method );
		$current = $url;
		$started = microtime( true );
		$headers = $headers + $this->default_headers;
		$origin  = self::origin( $url );

		// A verb goes onto the request line as it is. One with a space or a
		// line break in it writes a second request of the caller's choosing.
		if ( 1 !== preg_match( '/^[!#$%&\'*+.^_`|~0-9A-Z-]+$/D', $method ) ) {
			throw new \InvalidArgumentException( 'Not an HTTP method: ' . var_export( $method, true ) );
		}

		for ( $hop = 0; $hop <= $this->max_redirects; $hop++ ) {
			$pinned = null;

			// Whitespace or a control character is never part of a valid
			// URL, and parse_url() and curl each read one differently. The
			// policy refuses it too; this holds with the guard off as well,
			// for the first URL and every Location after it.
			if ( 1 === preg_match( '/[\x00-\x20\x7F]/', $current ) ) {
				return Response::failure( 'blocked: URL contains whitespace or a control character.' );
			}

			if ( null !== $this->ssrf ) {
				$check = $this->ssrf->validate( $current );

				if ( ! $check->ok ) {
					return Response::failure( 'blocked: ' . $check->error );
				}

				$pinned = $check;
			}

			$result = $this->execute( $method, $current, $body, $headers, $pinned, $sink );

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

				if ( self::origin( $current ) !== $origin ) {
					$headers = self::without_credentials( $headers );
				}

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

			if ( null === $sink && $this->max_bytes > 0 && strlen( $response_body ) > $this->max_bytes ) {
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
	 * When guarded, the connection is pinned to the validated address and
	 * checked against it once it is open: should curl have read the URL's
	 * host differently from the policy, and so looked the name up itself,
	 * the request is abandoned before a byte of it is sent. A guarded
	 * request never goes through a proxy, which would look the name up all
	 * over again on its own side.
	 *
	 * TLS certificates and host names are always verified; there is no
	 * switch to turn that off.
	 *
	 * @since 1.0.0
	 * @since 1.5.0 Checks the connected address against the pin, never uses a
	 *              proxy when guarded, and takes the headers already merged.
	 *
	 * @param non-empty-string          $method  Verb.
	 * @param string                    $url     URL.
	 * @param string|null               $body    Body.
	 * @param array<int|string, string> $headers Every header to send.
	 * @param SsrfResult|null           $pinned  Validated target, when guarded.
	 * @param \Closure|null             $sink    Receives a 2xx body as it arrives.
	 *
	 * @return array{status:int, body:string|false, content_type:string, error:string, location:string, headers:array<string,string>}
	 *
	 * @throws \InvalidArgumentException On a header or user agent containing
	 *                                   CR, LF or NUL.
	 */
	private function execute( string $method, string $url, ?string $body, array $headers, ?SsrfResult $pinned, ?\Closure $sink = null ): array {
		$handle           = curl_init( $url );
		$response_headers = array();
		$kept             = '';

		$options = array(
			CURLOPT_CUSTOMREQUEST   => $method,
			CURLOPT_RETURNTRANSFER  => true,
			CURLOPT_FOLLOWLOCATION  => false,
			CURLOPT_TIMEOUT         => $this->timeout,
			CURLOPT_CONNECTTIMEOUT  => $this->timeout,
			CURLOPT_PROTOCOLS       => self::PROTOCOLS,
			CURLOPT_REDIR_PROTOCOLS => self::PROTOCOLS,
			CURLOPT_SSL_VERIFYPEER  => true,
			CURLOPT_SSL_VERIFYHOST  => 2,
			CURLOPT_NOBODY          => 'HEAD' === $method,
			CURLOPT_HEADERFUNCTION  => static function ( \CurlHandle $handle, string $line ) use ( &$response_headers ): int {
				$parts = explode( ':', $line, 2 );

				if ( 2 === count( $parts ) ) {
					$response_headers[ strtolower( trim( $parts[0] ) ) ] = trim( $parts[1] );
				}

				return strlen( $line );
			},
		);

		if ( '' !== $this->user_agent ) {
			if ( 1 === preg_match( '/[\r\n\x00]/', $this->user_agent ) ) {
				throw new \InvalidArgumentException( 'User agent contains a line break.' );
			}

			$options[ CURLOPT_USERAGENT ] = $this->user_agent;
		}

		if ( array() !== $headers ) {
			$options[ CURLOPT_HTTPHEADER ] = self::normalize_headers( $headers );
		}

		if ( null !== $body && '' !== $body ) {
			$options[ CURLOPT_POSTFIELDS ] = $body;
		}

		if ( null !== $pinned ) {
			// Pin the connection to the address the policy validated, so
			// a second DNS answer cannot redirect us somewhere private.
			$options[ CURLOPT_RESOLVE ] = array( $pinned->resolve_entry() );
			$options[ CURLOPT_PROXY ]   = '';

			// And make sure it was. curl reads some URLs differently from
			// parse_url(), and a host it reads differently is a host it
			// resolves for itself, past the pin. Called once the connection
			// is up and before the request is written.
			$want = inet_pton( trim( $pinned->ip, '[]' ) );

			$options[ CURLOPT_PREREQFUNCTION ] = static fn ( \CurlHandle $handle, string $primary_ip ): int
				=> false !== $want && inet_pton( $primary_ip ) === $want ? CURL_PREREQFUNC_OK : CURL_PREREQFUNC_ABORT;
		}

		if ( null !== $sink ) {
			// A transfer is as long as the file is big, so the timeout
			// bounds connecting and stalling rather than the whole thing.
			$options[ CURLOPT_RETURNTRANSFER ]  = false;
			$options[ CURLOPT_TIMEOUT ]         = 0;
			$options[ CURLOPT_LOW_SPEED_LIMIT ] = 1;
			$options[ CURLOPT_LOW_SPEED_TIME ]  = max( 1, $this->timeout );
			$options[ CURLOPT_WRITEFUNCTION ]   = static function ( \CurlHandle $handle, string $chunk ) use ( $sink, &$kept ): int {
				$status = (int) curl_getinfo( $handle, CURLINFO_RESPONSE_CODE );

				if ( $status >= 200 && $status < 300 ) {
					$sink( $chunk );
				} elseif ( strlen( $kept ) < self::KEPT ) {
					// Not the body anybody asked for: an error document, or
					// a redirect's. Kept, briefly, to say what went wrong.
					$kept .= substr( $chunk, 0, self::KEPT - strlen( $kept ) );
				}

				return strlen( $chunk );
			};
		}

		if ( $this->max_bytes > 0 ) {
			// Abort mid-transfer rather than buffering an oversized body
			// and checking its length afterwards.
			$options[ CURLOPT_NOPROGRESS ]       = false;
			$options[ CURLOPT_PROGRESSFUNCTION ] = fn( \CurlHandle $handle, int $download_total, int $downloaded ): int
				=> ( $downloaded > $this->max_bytes || $download_total > $this->max_bytes ) ? 1 : 0;
		}

		curl_setopt_array( $handle, $options );

		$result = curl_exec( $handle );
		$out    = array(
			'status'       => (int) curl_getinfo( $handle, CURLINFO_HTTP_CODE ),
			// Streamed, curl_exec() answers true or false and the body has
			// gone to the sink; what is left is anything not passed on.
			'body'         => null !== $sink
				? ( true === $result ? $kept : false )
				: ( is_string( $result ) ? $result : false ),
			'content_type' => strtok( (string) curl_getinfo( $handle, CURLINFO_CONTENT_TYPE ), ';' ) ?: '',
			'error'        => curl_error( $handle ),
			'location'     => (string) curl_getinfo( $handle, CURLINFO_REDIRECT_URL ),
			'headers'      => $response_headers,
		);

		unset( $handle );

		return $out;
	}

	/**
	 * The origin of a URL: scheme, host and port, lowercase.
	 *
	 * @since 1.5.0
	 *
	 * @param string $url URL.
	 *
	 * @return string `scheme://host:port`, or '' when it does not parse.
	 */
	private static function origin( string $url ): string {
		$parts = parse_url( $url );

		if ( false === $parts || ! isset( $parts['host'] ) ) {
			return '';
		}

		$scheme = strtolower( $parts['scheme'] ?? '' );
		$port   = $parts['port'] ?? ( 'https' === $scheme ? 443 : 80 );

		return $scheme . '://' . strtolower( $parts['host'] ) . ':' . $port;
	}

	/**
	 * Headers with every credential-bearing one taken out.
	 *
	 * Handles both forms normalize_headers() accepts: `Name => value` and a
	 * preformatted `Name: value` line.
	 *
	 * @since 1.5.0
	 *
	 * @param array<int|string, string> $headers Headers.
	 *
	 * @return array<int|string, string>
	 */
	private static function without_credentials( array $headers ): array {
		return array_filter(
			$headers,
			static function ( string $value, int|string $name ): bool {
				$name = is_int( $name ) ? explode( ':', $value, 2 )[0] : $name;

				return ! in_array( strtolower( trim( $name ) ), self::CREDENTIALS, true );
			},
			ARRAY_FILTER_USE_BOTH
		);
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
	 * @return list<string>
	 *
	 * @throws \InvalidArgumentException On a header containing CR or LF.
	 */
	public static function normalize_headers( array $headers ): array {
		$out = array();

		foreach ( $headers as $name => $value ) {
			$line = is_int( $name ) ? $value : $name . ': ' . $value;

			if ( 1 === preg_match( '/[\r\n\x00]/', $line ) ) {
				throw new \InvalidArgumentException( 'Header contains a line break: ' . var_export( $name, true ) );
			}

			$out[] = $line;
		}

		return $out;
	}
}
