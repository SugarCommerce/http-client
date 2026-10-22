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
	 * The first twelve bytes of an IPv4-mapped IPv6 address, `::ffff:0:0/96`.
	 */
	private const string MAPPED_PREFIX = "\0\0\0\0\0\0\0\0\0\0\xff\xff";

	/**
	 * IPv4 blocks that are not the public internet.
	 *
	 * IANA's special-purpose registry, less nothing: this network, the
	 * RFC 1918 ranges, carrier-grade NAT, loopback, link-local (the cloud
	 * metadata service lives at 169.254.169.254), the protocol-assignment
	 * and documentation blocks, the 6to4 relay anycast, benchmarking,
	 * multicast and the reserved top of the space.
	 */
	private const array BLOCKED_V4 = array(
		'0.0.0.0/8',
		'10.0.0.0/8',
		'100.64.0.0/10',
		'127.0.0.0/8',
		'169.254.0.0/16',
		'172.16.0.0/12',
		'192.0.0.0/24',
		'192.0.2.0/24',
		'192.88.99.0/24',
		'192.168.0.0/16',
		'198.18.0.0/15',
		'198.51.100.0/24',
		'203.0.113.0/24',
		'224.0.0.0/4',
		'240.0.0.0/4',
	);

	/**
	 * IPv6 blocks that are not the public internet.
	 *
	 * Unspecified, loopback and the deprecated IPv4-compatible form (all of
	 * `::/96`), SIIT's IPv4-translated form, NAT64 (both the well-known and
	 * the local-use prefix), discard-only, the IETF protocol assignments
	 * (Teredo among them), documentation, 6to4, segment-routing, unique
	 * local, link-local, the retired site-local block and multicast. NAT64,
	 * 6to4, Teredo and SIIT carry an IPv4 address inside, so they reach
	 * `10.x` from an address PHP's own filters call public.
	 */
	private const array BLOCKED_V6 = array(
		'::/96',
		'::ffff:0:0:0/96',
		'64:ff9b::/96',
		'64:ff9b:1::/48',
		'100::/64',
		'2001::/23',
		'2001:db8::/32',
		'2002::/16',
		'3fff::/20',
		'5f00::/16',
		'fc00::/7',
		'fe80::/10',
		'fec0::/10',
		'ff00::/8',
	);

	/**
	 * @since 1.0.0
	 *
	 * @param list<int>    $allowed_ports   Ports that may be connected to.
	 * @param list<string> $allowed_schemes URL schemes that may be fetched.
	 * @param bool         $allow_private   Permit private and loopback
	 *                                      addresses. For local development
	 *                                      and tests only — this disables the
	 *                                      entire point of the class.
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
	 * @since 1.5.0 Refuses a host that is not a plain hostname or IP literal,
	 *              and a URL with whitespace or a control character in it.
	 *
	 * @param string $url Candidate URL.
	 *
	 * @return SsrfResult Success carries the address to pin to.
	 */
	public function validate( string $url ): SsrfResult {
		// parse_url() turns a control character in a host into an
		// underscore, which a hostname may contain, so
		// `http://example.com\n/` was checked as `example.com_` — a name
		// nobody asked for, and not the URL curl is handed. No valid URL
		// contains whitespace or a control character anywhere; refuse it
		// before it is parsed at all.
		if ( 1 === preg_match( '/[\x00-\x20\x7F]/', $url ) ) {
			return SsrfResult::rejected( 'URL contains whitespace or a control character.' );
		}

		$parts = parse_url( $url );

		if ( false === $parts || ! isset( $parts['host'] ) ) {
			return SsrfResult::rejected( 'URL could not be parsed.' );
		}

		$scheme = strtolower( $parts['scheme'] ?? '' );

		if ( ! in_array( $scheme, $this->allowed_schemes, true ) ) {
			return SsrfResult::rejected( 'Scheme "' . $scheme . '" is not allowed.' );
		}

		// Credentials in a URL are parsed inconsistently across libraries,
		// which is exactly what makes them useful for smuggling a host.
		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return SsrfResult::rejected( 'URLs with embedded credentials are not allowed.' );
		}

		$host = $parts['host'];

		if ( ! self::is_plain_host( $host ) ) {
			return SsrfResult::rejected( 'Host is not a valid hostname or IP address.' );
		}

		$port = $parts['port'] ?? ( 'https' === $scheme ? 443 : 80 );

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
	 * @return list<string> Empty on resolution failure.
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
				if ( isset( $record['ipv6'] ) && is_string( $record['ipv6'] ) ) {
					$ips[] = $record['ipv6'];
				}
			}
		}

		return array_values( array_unique( $ips ) );
	}

	/**
	 * Whether an address is routable on the public internet.
	 *
	 * The address is put into its canonical binary form first, so the same
	 * host spelled `0064:ff9b::a9fe:a9fe`, `::ffff:a9fe:a9fe` or
	 * `::ffff:169.254.169.254` meets the same rule as its tidy spelling. A
	 * URL may carry any of those, and a check that compares text is a check
	 * on how the attacker chose to write the address.
	 *
	 * @since 1.0.0
	 * @since 1.5.0 Compares canonical binary forms against IANA's
	 *              special-purpose registries, not PHP's filter flags alone.
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 *
	 * @return bool
	 */
	public static function is_public_ip( string $ip ): bool {
		$ip = trim( $ip, '[]' );

		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$packed = inet_pton( $ip );

		if ( false === $packed ) {
			return false;
		}

		// An IPv4-mapped IPv6 address reaches the same host as the v4 form,
		// so it is judged by the v4 rules.
		if ( 16 === strlen( $packed ) && str_starts_with( $packed, self::MAPPED_PREFIX ) ) {
			$packed = substr( $packed, 12 );
		}

		foreach ( 4 === strlen( $packed ) ? self::BLOCKED_V4 : self::BLOCKED_V6 as $cidr ) {
			if ( self::in_cidr( $packed, $cidr ) ) {
				return false;
			}
		}

		// PHP's own idea of private and reserved, as a second opinion.
		$canonical = (string) inet_ntop( $packed );

		return false !== filter_var( $canonical, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Whether a binary address falls inside a CIDR block.
	 *
	 * @since 1.5.0
	 *
	 * @param string $packed Address as inet_pton() returns it.
	 * @param string $cidr   Block, e.g. `10.0.0.0/8` or `fc00::/7`.
	 *
	 * @return bool False when the block is of the other family.
	 */
	private static function in_cidr( string $packed, string $cidr ): bool {
		[ $network, $bits ] = explode( '/', $cidr, 2 );

		$base = inet_pton( $network );
		$bits = (int) $bits;

		if ( false === $base || strlen( $base ) !== strlen( $packed ) ) {
			return false;
		}

		$whole = intdiv( $bits, 8 );

		if ( substr( $packed, 0, $whole ) !== substr( $base, 0, $whole ) ) {
			return false;
		}

		$rest = $bits % 8;

		if ( 0 === $rest ) {
			return true;
		}

		$mask = ( 0xFF << ( 8 - $rest ) ) & 0xFF;

		return ( ord( $packed[ $whole ] ) & $mask ) === ( ord( $base[ $whole ] ) & $mask );
	}

	/**
	 * Whether a URL host is spelled the way a resolver and curl agree on.
	 *
	 * Letters, digits, hyphens, dots and underscores, or a bracketed IPv6
	 * literal. An underscore is not valid in a hostname under RFC 952 and
	 * 1123 but turns up in real DNS names, so it stays; it is also what
	 * parse_url() makes of a control character, which is why validate()
	 * refuses those before parsing. Anything else is where parsers part
	 * company: curl decodes `%2e` in a host into a dot, parse_url() does
	 * not, so the name that was checked and the name that is connected to
	 * are two different names, and the connection is no longer pinned to
	 * anything. A zone index (`[fe80::1%25en0]`) and a raw Unicode name are
	 * refused for the same reason; convert an internationalised name to its
	 * `xn--` form first.
	 *
	 * @since 1.5.0
	 *
	 * @param string $host Host as parse_url() returned it.
	 *
	 * @return bool
	 */
	private static function is_plain_host( string $host ): bool {
		if ( str_starts_with( $host, '[' ) ) {
			return 1 === preg_match( '/^\[[0-9a-f:.]+\]$/iD', $host )
				&& false !== filter_var( substr( $host, 1, -1 ), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
		}

		return 1 === preg_match( '/^[a-z0-9_.-]{1,253}$/iD', $host );
	}
}
