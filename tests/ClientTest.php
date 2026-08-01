<?php
/**
 * Client test suite.
 *
 * Runs against a real PHP built-in server rather than a mocked
 * transport, because the things worth testing here — redirect handling,
 * connection pinning, size caps, timeouts — only exist at the transport
 * layer. A mock would test the mock.
 *
 * @package   SugarMill\HttpClient
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarMill\HttpClient\Tests;

use PHPUnit\Framework\Attributes\AfterClass;
use PHPUnit\Framework\Attributes\BeforeClass;
use PHPUnit\Framework\TestCase;
use SugarMill\HttpClient\Client;
use SugarMill\HttpClient\SsrfPolicy;

final class ClientTest extends TestCase {

	/**
	 * Handle for the built-in server process.
	 *
	 * @var resource|null
	 */
	private static $server = null;

	private static int $port = 0;

	#[BeforeClass]
	public static function start_server(): void {
		self::$port = random_int( 20000, 30000 );
		$root       = __DIR__ . '/fixtures';

		self::$server = proc_open(
			sprintf( '%s -S 127.0.0.1:%d -t %s', escapeshellarg( PHP_BINARY ), self::$port, escapeshellarg( $root ) ),
			array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ),
			$pipes
		);

		// Wait for it to accept connections.
		for ( $i = 0; $i < 100; $i++ ) {
			$socket = @fsockopen( '127.0.0.1', self::$port, $errno, $errstr, 0.1 );

			if ( false !== $socket ) {
				fclose( $socket );

				return;
			}

			usleep( 50000 );
		}

		self::markTestSkippedBecauseServerFailed();
	}

	#[AfterClass]
	public static function stop_server(): void {
		if ( is_resource( self::$server ) ) {
			proc_terminate( self::$server );
			proc_close( self::$server );
			self::$server = null;
		}
	}

	private static function markTestSkippedBecauseServerFailed(): void {
		self::stop_server();

		throw new \RuntimeException( 'Could not start the test HTTP server.' );
	}

	private function url( string $path ): string {
		return 'http://127.0.0.1:' . self::$port . '/' . ltrim( $path, '/' );
	}

	private function client(): Client {
		// Loopback, so the guard has to be told this is deliberate.
		return new Client( ssrf: SsrfPolicy::permissive() );
	}

	/* ─── Basic verbs ───────────────────────────────────────────────── */

	public function test_get_returns_a_body(): void {
		$response = $this->client()->get( $this->url( 'echo.php?msg=hello' ) );

		$this->assertTrue( $response->ok );
		$this->assertSame( 200, $response->status );
		$this->assertStringContainsString( 'hello', $response->body );
		$this->assertGreaterThan( 0.0, $response->duration );
	}

	public function test_post_sends_a_body(): void {
		$response = $this->client()->post( $this->url( 'echo.php' ), 'payload=abc' );

		$this->assertTrue( $response->ok );
		$this->assertStringContainsString( 'payload=abc', $response->body );
	}

	public function test_post_json_sets_the_content_type(): void {
		$response = $this->client()->post_json( $this->url( 'echo.php' ), array( 'a' => 1 ) );

		$this->assertTrue( $response->ok );
		$this->assertStringContainsString( 'application/json', $response->body );
		$this->assertStringContainsString( '{"a":1}', $response->body );
	}

	public function test_json_decodes_a_json_response(): void {
		$response = $this->client()->get( $this->url( 'json.php' ) );

		$this->assertSame( array( 'ok' => true, 'value' => 42 ), $response->json() );
		$this->assertSame( 'application/json', $response->content_type );
	}

	public function test_headers_are_sent_and_received(): void {
		$response = $this->client()->get( $this->url( 'echo.php' ), array( 'X-Test' => 'abc' ) );

		$this->assertStringContainsString( 'abc', $response->body );
		$this->assertNotNull( $response->header( 'content-type' ) );
	}

	public function test_head_returns_no_body(): void {
		$response = $this->client()->head( $this->url( 'echo.php' ) );

		$this->assertSame( 200, $response->status );
		$this->assertSame( '', $response->body );
	}

	/* ─── Status handling ───────────────────────────────────────────── */

	public function test_a_404_is_a_client_error(): void {
		$response = $this->client()->get( $this->url( 'status.php?code=404' ) );

		$this->assertFalse( $response->ok );
		$this->assertTrue( $response->client_error() );
		$this->assertFalse( $response->server_error() );
		$this->assertFalse( $response->transport_error() );
		$this->assertSame( 'HTTP 404', $response->error );
	}

	public function test_a_500_is_a_server_error(): void {
		$response = $this->client()->get( $this->url( 'status.php?code=500' ) );

		$this->assertTrue( $response->server_error() );
	}

	public function test_a_refused_connection_is_a_transport_error(): void {
		$response = ( new Client( timeout: 2, ssrf: SsrfPolicy::permissive() ) )->get( 'http://127.0.0.1:1/' );

		$this->assertTrue( $response->transport_error() );
		$this->assertSame( 0, $response->status );
		$this->assertNotSame( '', $response->error );
	}

	/* ─── Redirects ─────────────────────────────────────────────────── */

	public function test_redirects_are_not_followed_by_default(): void {
		$response = $this->client()->get( $this->url( 'redirect.php?to=/json.php' ) );

		$this->assertSame( 302, $response->status );
		$this->assertFalse( $response->ok );
	}

	public function test_redirects_are_followed_when_enabled(): void {
		$response = $this->client()->following_redirects( 3 )->get( $this->url( 'redirect.php?to=/json.php' ) );

		$this->assertTrue( $response->ok );
		$this->assertSame( array( 'ok' => true, 'value' => 42 ), $response->json() );
	}

	public function test_the_redirect_budget_is_enforced(): void {
		$response = $this->client()->following_redirects( 2 )->get( $this->url( 'loop.php' ) );

		$this->assertFalse( $response->ok );
		$this->assertSame( 'too many redirects', $response->error );
	}

	/**
	 * The reason curl's own FOLLOWLOCATION is not used: it validates the
	 * first URL and then follows a 302 anywhere at all. Here every hop
	 * goes back through the policy, so a redirect into private space is
	 * refused even though the original URL was fine.
	 */
	public function test_a_redirect_into_private_space_is_blocked(): void {
		$client   = new Client( max_redirects: 3, ssrf: new SsrfPolicy( allowed_ports: array(), allow_private: false ) );
		$response = $client->get( $this->url( 'redirect.php?to=http://169.254.169.254/' ) );

		// The first hop is loopback, so this is blocked immediately —
		// which is itself the correct outcome.
		$this->assertFalse( $response->ok );
		$this->assertStringStartsWith( 'blocked:', $response->error );
	}

	/* ─── SSRF guard ────────────────────────────────────────────────── */

	public function test_the_guard_is_on_by_default(): void {
		$response = ( new Client() )->get( $this->url( 'echo.php' ) );

		$this->assertFalse( $response->ok );
		$this->assertStringStartsWith( 'blocked:', $response->error );
		$this->assertTrue( $response->transport_error() );
	}

	public function test_the_metadata_service_is_blocked(): void {
		$response = ( new Client( timeout: 2 ) )->get( 'http://169.254.169.254/latest/meta-data/' );

		$this->assertFalse( $response->ok );
		$this->assertStringStartsWith( 'blocked:', $response->error );
	}

	public function test_file_urls_are_blocked(): void {
		$response = ( new Client() )->get( 'file:///etc/passwd' );

		$this->assertFalse( $response->ok );
		$this->assertSame( '', $response->body );
	}

	public function test_the_guard_can_be_disabled_explicitly(): void {
		$this->assertTrue( ( new Client() )->without_ssrf()->get( $this->url( 'echo.php' ) )->ok );
	}

	/* ─── Size cap ──────────────────────────────────────────────────── */

	public function test_oversized_responses_are_refused(): void {
		$response = $this->client()->with_max_bytes( 1024 )->get( $this->url( 'big.php?kb=64' ) );

		$this->assertFalse( $response->ok );
	}

	public function test_responses_within_the_cap_are_returned(): void {
		$response = $this->client()->with_max_bytes( 1048576 )->get( $this->url( 'big.php?kb=8' ) );

		$this->assertTrue( $response->ok );
		$this->assertSame( 8 * 1024, strlen( $response->body ) );
	}

	/* ─── Timeout ───────────────────────────────────────────────────── */

	public function test_slow_responses_time_out(): void {
		$response = ( new Client( timeout: 1, ssrf: SsrfPolicy::permissive() ) )->get( $this->url( 'slow.php?seconds=3' ) );

		$this->assertFalse( $response->ok );
		$this->assertTrue( $response->transport_error() );
	}

	/* ─── Header safety ─────────────────────────────────────────────── */

	public function test_header_injection_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );
		Client::normalize_headers( array( 'X-Evil' => "a\r\nX-Injected: yes" ) );
	}

	public function test_headers_normalise_from_a_map_or_a_list(): void {
		$this->assertSame( array( 'A: b' ), Client::normalize_headers( array( 'A' => 'b' ) ) );
		$this->assertSame( array( 'A: b' ), Client::normalize_headers( array( 'A: b' ) ) );
	}

	/* ─── Immutable configuration ───────────────────────────────────── */

	public function test_configuration_helpers_return_new_instances(): void {
		$client = new Client();

		$this->assertNotSame( $client, $client->with_timeout( 30 ) );
		$this->assertSame( 30, $client->with_timeout( 30 )->timeout );
		$this->assertSame( 5, $client->following_redirects( 5 )->max_redirects );
		$this->assertNull( $client->without_ssrf()->ssrf );
		$this->assertSame( 10, $client->with_timeout( 30 )->with_timeout( 10 )->timeout );
	}

	public function test_default_headers_are_merged(): void {
		$response = $this->client()->with_headers( array( 'X-Default' => 'yes' ) )->get( $this->url( 'echo.php' ) );

		$this->assertStringContainsString( 'yes', $response->body );
	}
}
