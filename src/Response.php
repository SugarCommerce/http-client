<?php
/**
 * An HTTP response, or the reason there wasn't one.
 *
 * @package   Sugar\HttpClient
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace Sugar\HttpClient;

/**
 * Class Response
 *
 * Returned for every outcome, including transport failures. The client
 * does not throw for a refused connection, a timeout, or a blocked URL,
 * because "the remote end is unreachable" is a normal thing for an
 * outbound request and forcing a try/catch around every call encourages
 * people to swallow it.
 *
 * Check {@see self::$ok}, or {@see self::successful()} for the same
 * thing spelled out.
 *
 * @since 1.0.0
 */
final readonly class Response {

	/**
	 * @since 1.0.0
	 *
	 * @param bool                    $ok           True on a 2xx.
	 * @param int                     $status       HTTP status, or 0 when
	 *                                              the request never
	 *                                              completed.
	 * @param string                  $body         Response body.
	 * @param string                  $content_type `Content-Type`, without
	 *                                              parameters.
	 * @param string                  $error        Short reason on failure.
	 * @param array<string, string>   $headers      Response headers, keyed
	 *                                              lowercase.
	 * @param float                   $duration     Seconds spent.
	 * @param string                  $final_url    URL after redirects.
	 */
	public function __construct(
		public bool $ok,
		public int $status,
		public string $body = '',
		public string $content_type = '',
		public string $error = '',
		public array $headers = array(),
		public float $duration = 0.0,
		public string $final_url = '',
	) {}

	/**
	 * Build a failure response.
	 *
	 * @since 1.0.0
	 *
	 * @param string $error  Reason.
	 * @param int    $status Status, if one was received.
	 *
	 * @return self
	 */
	public static function failure( string $error, int $status = 0 ): self {
		return new self( false, $status, error: $error );
	}

	/**
	 * Whether the request returned a 2xx.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function successful(): bool {
		return $this->ok;
	}

	/**
	 * Whether the request did not return a 2xx.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function failed(): bool {
		return ! $this->ok;
	}

	/**
	 * Whether the failure was the remote end's fault (5xx).
	 *
	 * The distinction that matters for retries: a 500 is worth trying
	 * again, a 404 is not.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function server_error(): bool {
		return $this->status >= 500 && $this->status < 600;
	}

	/**
	 * Whether the request was rejected as malformed or unauthorised (4xx).
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function client_error(): bool {
		return $this->status >= 400 && $this->status < 500;
	}

	/**
	 * Whether the request never reached the remote end at all.
	 *
	 * Timeout, DNS failure, refused connection, or blocked by the SSRF
	 * policy. Distinguished from an HTTP error because nothing was
	 * served — retrying is reasonable, and the URL may simply be wrong.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function transport_error(): bool {
		return 0 === $this->status;
	}

	/**
	 * Decode the body as JSON.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $associative Return arrays rather than objects.
	 *
	 * @return mixed Null when the body is absent or not valid JSON.
	 */
	public function json( bool $associative = true ): mixed {
		if ( '' === $this->body ) {
			return null;
		}

		try {
			return json_decode( $this->body, $associative, 512, JSON_THROW_ON_ERROR );
		} catch ( \JsonException ) {
			return null;
		}
	}

	/**
	 * Read a response header, case-insensitively.
	 *
	 * @since 1.0.0
	 *
	 * @param string $name Header name.
	 *
	 * @return string|null
	 */
	public function header( string $name ): ?string {
		return $this->headers[ strtolower( $name ) ] ?? null;
	}

	/**
	 * The array shape older `wp_remote_*`-style code expects.
	 *
	 * @since 1.0.0
	 *
	 * @return array{ok:bool, status:int, body:string, content_type:string, error:string}
	 */
	public function to_array(): array {
		return array(
			'ok'           => $this->ok,
			'status'       => $this->status,
			'body'         => $this->body,
			'content_type' => $this->content_type,
			'error'        => $this->error,
		);
	}
}
