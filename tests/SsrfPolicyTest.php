<?php
/**
 * SsrfPolicy test suite.
 *
 * @package   SugarCommerce\HttpClient
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\HttpClient\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\HttpClient\SsrfPolicy;

final class SsrfPolicyTest extends TestCase {

	/* ─── Address classification ────────────────────────────────────── */

	#[DataProvider( 'private_addresses' )]
	public function test_private_and_reserved_addresses_are_rejected( string $ip ): void {
		$this->assertFalse( SsrfPolicy::is_public_ip( $ip ) );
	}

	/** @return array<string, array{0: string}> */
	public static function private_addresses(): array {
		return array(
			'loopback'            => array( '127.0.0.1' ),
			'loopback range'      => array( '127.255.255.254' ),
			'rfc1918 10'          => array( '10.0.0.1' ),
			'rfc1918 172'         => array( '172.16.5.4' ),
			'rfc1918 192'         => array( '192.168.1.1' ),
			'link-local'          => array( '169.254.169.254' ),
			'this network'        => array( '0.0.0.0' ),
			'cgnat low'           => array( '100.64.0.1' ),
			'cgnat high'          => array( '100.127.255.254' ),
			'ipv6 loopback'       => array( '::1' ),
			'ipv6 unique local'   => array( 'fd00::1' ),
			'ipv6 link-local'     => array( 'fe80::1' ),
			'ipv4-mapped private' => array( '::ffff:10.0.0.1' ),
			'ipv4-mapped meta'    => array( '::ffff:169.254.169.254' ),
			'nat64'               => array( '64:ff9b::a00:1' ),
			'6to4'                => array( '2002:0a00:0001::' ),
			'nat64 leading zeros' => array( '0064:ff9b::a9fe:a9fe' ),
			'nat64 local-use'     => array( '64:ff9b:1::a9fe:a9fe' ),
			'ipv4-mapped hex'     => array( '::ffff:a9fe:a9fe' ),
			'ipv4-translated'     => array( '::ffff:0:a9fe:a9fe' ),
			'ipv4-compatible'     => array( '::a9fe:a9fe' ),
			'teredo'              => array( '2001::5ef5:79fd' ),
			'ipv6 documentation'  => array( '2001:db8::1' ),
			'ipv6 site-local'     => array( 'fec0::1' ),
			'ipv6 multicast'      => array( 'ff02::1' ),
			'ipv6 discard'        => array( '100::1' ),
			'ietf protocol'       => array( '192.0.0.170' ),
			'benchmarking'        => array( '198.18.0.1' ),
			'documentation'       => array( '203.0.113.7' ),
			'multicast'           => array( '224.0.0.1' ),
			'broadcast'           => array( '255.255.255.255' ),
			'not an ip'           => array( 'not-an-ip' ),
			'empty'               => array( '' ),
		);
	}

	#[DataProvider( 'public_addresses' )]
	public function test_public_addresses_are_accepted( string $ip ): void {
		$this->assertTrue( SsrfPolicy::is_public_ip( $ip ) );
	}

	/** @return array<string, array{0: string}> */
	public static function public_addresses(): array {
		return array(
			'google dns'      => array( '8.8.8.8' ),
			'cloudflare dns'  => array( '1.1.1.1' ),
			'arbitrary v4'    => array( '93.184.216.34' ),
			'just above cgnat' => array( '100.128.0.1' ),
			'just below cgnat' => array( '100.63.255.255' ),
			'ipv6 public'     => array( '2606:4700:4700::1111' ),
			'mapped public'   => array( '::ffff:8.8.8.8' ),
		);
	}

	/* ─── Scheme and credential rules ───────────────────────────────── */

	#[DataProvider( 'rejected_urls' )]
	public function test_dangerous_urls_are_rejected( string $url ): void {
		$this->assertFalse( ( new SsrfPolicy() )->validate( $url )->ok );
	}

	/** @return array<string, array{0: string}> */
	public static function rejected_urls(): array {
		return array(
			'file scheme'      => array( 'file:///etc/passwd' ),
			'gopher scheme'    => array( 'gopher://example.com/' ),
			'dict scheme'      => array( 'dict://example.com/' ),
			'ftp scheme'       => array( 'ftp://example.com/' ),
			'no scheme'        => array( 'example.com/path' ),
			'credentials'      => array( 'http://user:pass@example.com/' ),
			'user only'        => array( 'http://real.com@127.0.0.1/' ),
			'loopback host'    => array( 'http://127.0.0.1/' ),
			'loopback name'    => array( 'http://localhost/' ),
			'metadata service' => array( 'http://169.254.169.254/latest/meta-data/' ),
			'private literal'  => array( 'http://10.0.0.1/' ),
			'ipv6 loopback'    => array( 'http://[::1]/' ),
			'mapped metadata'  => array( 'http://[::ffff:a9fe:a9fe]/' ),
			'nat64 metadata'   => array( 'http://[0064:ff9b::a9fe:a9fe]/' ),
			'empty'            => array( '' ),
		);
	}

	/**
	 * curl decodes `%2e` in a host to a dot and parse_url() does not, so a
	 * host spelled that way is checked as one name and connected to as
	 * another. Anything outside a plain hostname is refused before it is
	 * resolved.
	 */
	#[DataProvider( 'unplain_hosts' )]
	public function test_a_host_parsers_disagree_on_is_refused( string $url ): void {
		$result = SsrfPolicy::permissive()->validate( $url );

		$this->assertFalse( $result->ok );
		$this->assertStringContainsString( 'not a valid hostname', $result->error );
	}

	/** @return array<string, array{0: string}> */
	public static function unplain_hosts(): array {
		return array(
			'percent-encoded dot' => array( 'http://169%2e254%2e169%2e254/' ),
			'percent-encoded'     => array( 'http://local%68ost/' ),
			'zone index'          => array( 'http://[fe80::1%25en0]/' ),
			'unicode'             => array( 'http://exämple.com/' ),
		);
	}

	/**
	 * parse_url() turns a control character in a host into an underscore,
	 * and an underscore is allowed in a host, so `http://example.com\n/`
	 * was validated as `example.com_`. Whitespace and control characters
	 * are refused anywhere in the URL, before it is parsed.
	 */
	#[DataProvider( 'unsafe_character_urls' )]
	public function test_a_url_with_whitespace_or_a_control_character_is_refused( string $url ): void {
		$result = SsrfPolicy::permissive()->validate( $url );

		$this->assertFalse( $result->ok );
		$this->assertSame( 'URL contains whitespace or a control character.', $result->error );
	}

	/** @return array<string, array{0: string}> */
	public static function unsafe_character_urls(): array {
		return array(
			'newline in host'   => array( "http://example.com\n/" ),
			'return in host'    => array( "http://example.com\r/" ),
			'tab in host'       => array( "http://example.com\t/" ),
			'nul in host'       => array( "http://example.com\0/" ),
			'delete in host'    => array( "http://example.com\x7F/" ),
			'unit sep in host'  => array( "http://example.com\x1F/" ),
			'space in host'     => array( 'http://exa mple.com/' ),
			'space before path' => array( 'http://example.com /' ),
			'newline in path'   => array( "http://example.com/a\nb" ),
			'return in path'    => array( "http://example.com/a\r\nHost: internal" ),
			'tab in path'       => array( "http://example.com/a\tb" ),
			'nul in path'       => array( "http://example.com/a\0b" ),
			'space in path'     => array( 'http://example.com/a b' ),
			'space in query'    => array( 'http://example.com/?q=a b' ),
			'trailing newline'  => array( "http://example.com/\n" ),
			'leading space'     => array( ' http://example.com/' ),
			'loopback newline'  => array( "http://127.0.0.1\n/" ),
		);
	}

	/**
	 * An underscore is not valid in a hostname under RFC 952 and 1123, but
	 * real DNS names carry one, so it is still a plain host. The refusal
	 * above is what keeps a control character from arriving as one.
	 */
	public function test_an_underscore_in_a_host_is_still_plain(): void {
		$is_plain = new \ReflectionMethod( SsrfPolicy::class, 'is_plain_host' );

		$this->assertTrue( $is_plain->invoke( null, '_dmarc.example.com' ) );
		$this->assertTrue( $is_plain->invoke( null, 'my_host.example.com' ) );
	}

	/**
	 * parse_url() turns a control character into an underscore, so
	 * validate() does not hand this check a newline today. It must hold on
	 * its own all the same, and `$` also matches just before a final
	 * newline.
	 */
	#[DataProvider( 'newline_hosts' )]
	public function test_a_host_ending_in_a_newline_is_not_plain( string $host ): void {
		$is_plain = new \ReflectionMethod( SsrfPolicy::class, 'is_plain_host' );

		$this->assertFalse( $is_plain->invoke( null, $host ) );
		$this->assertTrue( $is_plain->invoke( null, rtrim( $host ) ) );
	}

	/** @return array<string, array{0: string}> */
	public static function newline_hosts(): array {
		return array(
			'name'         => array( "example.com\n" ),
			'ipv6 literal' => array( "[2606:4700:4700::1111]\n" ),
		);
	}

		/* ─── Port allowlist ────────────────────────────────────────────── */

	/**
	 * A public IP on port 6379 is still somebody's Redis. HTTP request
	 * bodies can be shaped to look like valid commands to plenty of
	 * line-based protocols, so restricting the port matters even when the
	 * address check passes.
	 */
	#[DataProvider( 'service_ports' )]
	public function test_non_http_ports_are_rejected_by_default( int $port ): void {
		$result = ( new SsrfPolicy() )->validate( 'http://example.com:' . $port . '/' );

		$this->assertFalse( $result->ok );
		$this->assertStringContainsString( 'Port', $result->error );
	}

	/** @return array<string, array{0: int}> */
	public static function service_ports(): array {
		return array(
			'ssh'       => array( 22 ),
			'smtp'      => array( 25 ),
			'mysql'     => array( 3306 ),
			'postgres'  => array( 5432 ),
			'redis'     => array( 6379 ),
			'memcached' => array( 11211 ),
			'elastic'   => array( 9200 ),
		);
	}

	public function test_extra_ports_can_be_allowed(): void {
		$policy = new SsrfPolicy( allowed_ports: array( 80, 443, 8080 ) );

		$this->assertTrue( $policy->validate( 'http://example.com:8080/' )->ok );
	}

	public function test_an_empty_port_list_allows_any_port(): void {
		$this->assertTrue( SsrfPolicy::permissive()->validate( 'http://127.0.0.1:9999/' )->ok );
	}

	/* ─── Permissive mode ───────────────────────────────────────────── */

	public function test_permissive_mode_allows_loopback(): void {
		$this->assertTrue( SsrfPolicy::permissive()->validate( 'http://127.0.0.1:8080/' )->ok );
	}

	public function test_permissive_mode_still_rejects_dangerous_schemes(): void {
		$this->assertFalse( SsrfPolicy::permissive()->validate( 'file:///etc/passwd' )->ok );
	}

	public function test_permissive_mode_still_rejects_credentials(): void {
		$this->assertFalse( SsrfPolicy::permissive()->validate( 'http://a:b@127.0.0.1/' )->ok );
	}

	/* ─── Successful validation ─────────────────────────────────────── */

	public function test_a_valid_url_yields_a_pinnable_target(): void {
		$result = SsrfPolicy::permissive()->validate( 'http://127.0.0.1:8080/path' );

		$this->assertTrue( $result->ok );
		$this->assertSame( 'http', $result->scheme );
		$this->assertSame( '127.0.0.1', $result->host );
		$this->assertSame( 8080, $result->port );
		$this->assertSame( '127.0.0.1:8080:127.0.0.1', $result->resolve_entry() );
	}

	/**
	 * curl documents an IPv6 address in a resolve entry as bracketed. Bare,
	 * its colons are the field separator too.
	 */
	public function test_an_ipv6_pin_is_bracketed(): void {
		$result = SsrfPolicy::permissive()->validate( 'http://[::1]:8080/path' );

		$this->assertTrue( $result->ok );
		$this->assertSame( '::1', $result->ip );
		$this->assertSame( '[::1]:8080:[::1]', $result->resolve_entry() );
	}

	public function test_default_ports_are_inferred_from_the_scheme(): void {
		$policy = SsrfPolicy::permissive();

		$this->assertSame( 80, $policy->validate( 'http://127.0.0.1/' )->port );
		$this->assertSame( 443, $policy->validate( 'https://127.0.0.1/' )->port );
	}

	public function test_an_unresolvable_host_is_rejected(): void {
		$result = ( new SsrfPolicy() )->validate( 'http://this-host-does-not-exist.invalid/' );

		$this->assertFalse( $result->ok );
		$this->assertStringContainsString( 'resolve', $result->error );
	}

	/* ─── Resolution ────────────────────────────────────────────────── */

	public function test_ip_literals_resolve_to_themselves(): void {
		$this->assertSame( array( '8.8.8.8' ), SsrfPolicy::resolve( '8.8.8.8' ) );
		$this->assertSame( array( '::1' ), SsrfPolicy::resolve( '[::1]' ) );
	}

	public function test_an_unresolvable_host_returns_nothing(): void {
		$this->assertSame( array(), SsrfPolicy::resolve( 'this-host-does-not-exist.invalid' ) );
	}
}
