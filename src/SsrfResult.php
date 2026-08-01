<?php
/**
 * Outcome of an SSRF policy check.
 *
 * @package   SugarMill\HttpClient
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarMill\HttpClient;

/**
 * Class SsrfResult
 *
 * On success this carries the address the connection must be pinned to.
 * Validating a hostname and then letting curl resolve it again is not a
 * check at all — DNS can answer differently the second time, which is
 * the whole DNS-rebinding technique.
 *
 * @since 1.0.0
 */
final readonly class SsrfResult {

	/**
	 * @since 1.0.0
	 *
	 * @param bool   $ok     Whether the URL may be fetched.
	 * @param string $error  Reason for rejection, or ''.
	 * @param string $scheme Validated scheme.
	 * @param string $host   Validated host.
	 * @param int    $port   Resolved port.
	 * @param string $ip     Address to pin the connection to.
	 */
	private function __construct(
		public bool $ok,
		public string $error = '',
		public string $scheme = '',
		public string $host = '',
		public int $port = 0,
		public string $ip = '',
	) {}

	/**
	 * A URL that passed.
	 *
	 * @since 1.0.0
	 *
	 * @param string $scheme Scheme.
	 * @param string $host   Host.
	 * @param int    $port   Port.
	 * @param string $ip     Address to pin to.
	 *
	 * @return self
	 */
	public static function allowed( string $scheme, string $host, int $port, string $ip ): self {
		return new self( true, '', $scheme, $host, $port, $ip );
	}

	/**
	 * A URL that failed.
	 *
	 * @since 1.0.0
	 *
	 * @param string $error Reason, safe to log but not to echo to a user —
	 *                      it reveals your internal network shape.
	 *
	 * @return self
	 */
	public static function rejected( string $error ): self {
		return new self( false, $error );
	}

	/**
	 * The `host:port:ip` triple curl wants for connection pinning.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function resolve_entry(): string {
		return $this->host . ':' . $this->port . ':' . $this->ip;
	}
}
