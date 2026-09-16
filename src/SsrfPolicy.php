<?php
/**
 * Server-side request forgery policy.
 *
 * @package   SugarCommerce\HttpClient
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\HttpClient;

/**
 * Class SsrfPolicy
 *
 * Decides whether a URL is safe to fetch when the URL came from someone
 * other than you — a webhook endpoint an operator configured, an
 * "import from URL" field, an avatar someone pasted.
 *
 * The attack is that your server has network reach nobody else does. It
 * can see `169.254.169.254` (cloud instance credentials), `10.x` (your
 * database), `127.0.0.1` (admin panels bound to loopback). A URL field
 * is a request to make your server fetch something on the attacker's
 * behalf, and without a policy it will happily do it.
 *
 * What this enforces:
 *
 *   - **Scheme allowlist.** `http` and `https` only. No `file://`,
 *     `gopher://`, `dict://` — the classic protocol-smuggling routes.
 *   - **Port allowlist.** 80 and 443 by default. A public IP on port
 *     6379 is still your Redis, and an HTTP request body can be shaped
 *     to look like valid commands to plenty of line-based protocols.
 *   - **Every resolved address must be public.** Not the first one —
 *     all of them. A hostname answering with one public and one private
 *     address is a rebinding attempt, not a misconfiguration.
 *   - **No credentials in the URL.** `http://real.com@internal/` is
 *     read differently by different parsers; refusing it avoids the
 *     whole class.
 *   - **IPv6 transition ranges.** NAT64 (`64:ff9b::/96`) and 6to4
 *     (`2002::/16`) embed IPv4 addresses, so they reach `10.x` from a
 *     v6 address that PHP's own filters consider public.
 *
 * Validation alone is not enough — DNS can answer differently between
 * the check and the connection. {@see Client} pins the connection to the
 * address validated here, and re-validates every redirect hop.
 *
 * @since 1.0.0
 */
final readonly class SsrfPolicy {

	/**
	 * @since 1.0.0
	 *
	 * @param int[]    $allowed_ports   Ports that may be connected to.
	 * @param string[] $allowed_schemes URL schemes that may be fetched.
	 * @param bool     $allow_private   Permit private and loopback
	 *                                  addresses. For local development
	 *                                  and tests only — this disables the
	 *                                  entire point of the class.
	 */
	public function __construct(
		public array $allowed_ports = array( 80, 443 ),
		public array $allowed_schemes = array( 'http', 'https' ),
		public bool $allow_private = false,
	) {}

	/**
	 * A policy that permits private addresses and any port.
	 *
	 * For talking to services on your own network in development, or in
	 * tests. Never reachable from user input in production.
	 *
	 * @since 1.0.0
	 *
	 * @return self
	 */
	public static function permissive(): self {
		return new self( allowed_ports: array(), allow_private: true );
	}

	/**
	 * Validate a URL and resolve it to a pinned address.
	 *
	 * @since 1.0.0
	 *
	 * @param string $url Candidate URL.
	 *
	 * @return SsrfResult Success carries the address to pin to.
	 */
	public function validate( string $url ): SsrfResult {
		$parts = parse_url( $url );

		if ( false === $parts || ! isset( $parts['host'] ) ) {
			return SsrfResult::rejected( 'URL could not be parsed.' );
		}

		$scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );

		if ( ! in_array( $scheme, $this->allowed_schemes, true ) ) {
			return SsrfResult::rejected( 'Scheme "' . $scheme . '" is not allowed.' );
		}

		// Credentials in a URL are parsed inconsistently across libraries,
		// which is exactly what makes them useful for smuggling a host.
		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return SsrfResult::rejected( 'URLs with embedded credentials are not allowed.' );
		}

		$host = (string) $parts['host'];
		$port = (int) ( $parts['port'] ?? ( 'https' === $scheme ? 443 : 80 ) );

		if ( array() !== $this->allowed_ports && ! in_array( $port, $this->allowed_ports, true ) ) {
			return SsrfResult::rejected( 'Port ' . $port . ' is not allowed.' );
		}

		$ips = self::resolve( $host );

		if ( array() === $ips ) {
			return SsrfResult::rejected( 'Host could not be resolved.' );
		}

		if ( ! $this->allow_private ) {
			foreach ( $ips as $ip ) {
				// Every answer must pass. One private address among
				// several public ones is a rebinding attempt.
				if ( ! self::is_public_ip( $ip ) ) {
					return SsrfResult::rejected( 'Host resolves to a private or reserved address.' );
				}
			}
		}

		return SsrfResult::allowed( $scheme, $host, $port, $ips[0] );
	}

	/**
	 * Resolve a hostname to every A and AAAA answer.
	 *
	 * An IP literal is returned unchanged.
	 *
	 * @since 1.0.0
	 *
	 * @param string $host Hostname or IP literal.
	 *
	 * @return string[] Empty on resolution failure.
	 */
	public static function resolve( string $host ): array {
		$host = trim( $host, '[]' );

		if ( false !== filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return array( $host );
		}

		$ips = array();
		$a   = @gethostbynamel( $host );

		if ( is_array( $a ) ) {
			$ips = $a;
		}

		$aaaa = @dns_get_record( $host, DNS_AAAA );

		if ( is_array( $aaaa ) ) {
			foreach ( $aaaa as $record ) {
				if ( isset( $record['ipv6'] ) ) {
					$ips[] = (string) $record['ipv6'];
				}
			}
		}

		return array_values( array_unique( $ips ) );
	}

	/**
	 * Whether an address is routable on the public internet.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 *
	 * @return bool
	 */
	public static function is_public_ip( string $ip ): bool {
		$ip = trim( $ip, '[]' );

		// An IPv4-mapped IPv6 address reaches the same host as the v4 form,
		// so normalise before applying the v4 rules.
		if ( 1 === preg_match( '/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i', $ip, $m ) ) {
			$ip = $m[1];
		}

		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		// NAT64 and 6to4 embed an IPv4 address inside an IPv6 one that
		// PHP's filters consider perfectly public, which makes them a
		// route to 10.x that the obvious checks miss.
		$lower = strtolower( $ip );

		if ( str_starts_with( $lower, '64:ff9b:' ) || str_starts_with( $lower, '2002:' ) ) {
			return false;
		}

		if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return false;
		}

		// Carrier-grade NAT (100.64.0.0/10) is absent from PHP's reserved
		// set but is routinely used for internal infrastructure.
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$long = ip2long( $ip );

			if ( false !== $long && ( $long & 0xFFC00000 ) === ( ip2long( '100.64.0.0' ) & 0xFFC00000 ) ) {
				return false;
			}
		}

		return true;
	}
}
