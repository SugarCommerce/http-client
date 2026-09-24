<?php
/**
 * Fake test suite.
 *
 * @package   SugarCommerce\HttpClient
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.2.0
 */

declare( strict_types=1 );

namespace SugarCommerce\HttpClient\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\HttpClient\{Client, Fake, Response};

final class FakeTest extends TestCase {

	public function test_it_stands_in_for_a_client(): void {
		$this->assertInstanceOf( Client::class, new Fake() );
	}

	public function test_an_unscripted_request_gets_a_bare_200(): void {
		$response = ( new Fake() )->get( 'https://example.com/' );

		$this->assertTrue( $response->ok );
		$this->assertSame( 200, $response->status );
	}

	public function test_a_strict_fake_fails_what_nobody_scripted(): void {
		$response = Fake::strict()->post( 'https://example.com/hook', '{}' );

		$this->assertFalse( $response->ok );
		$this->assertSame( 'unscripted: POST https://example.com/hook', $response->error );
	}

	public function test_a_route_answers_by_verb_and_url_glob(): void {
		$http = ( new Fake() )->on( 'GET', 'https://api.test/v1/things/*', new Response( true, 200, '{"id":7}' ) );

		$this->assertSame( array( 'id' => 7 ), $http->get( 'https://api.test/v1/things/7?expand=x' )->json() );
		$this->assertSame( '', $http->post( 'https://api.test/v1/things/7', '' )->body );
	}

	public function test_the_first_matching_route_wins(): void {
		$http = ( new Fake() )
			->on( '*', 'https://api.test/special', new Response( true, 201 ) )
			->on( '*', 'https://api.test/*', new Response( true, 202 ) );

		$this->assertSame( 201, $http->get( 'https://api.test/special' )->status );
		$this->assertSame( 202, $http->get( 'https://api.test/other' )->status );
	}

	/**
	 * An outage followed by recovery: the route that is used up stops
	 * matching and the next one takes over.
	 */
	public function test_a_limited_route_runs_out(): void {
		$http = ( new Fake() )
			->on( 'GET', '*', Response::failure( 'timeout' ), times: 2 )
			->on( 'GET', '*', new Response( true, 200, 'ok' ) );

		$this->assertFalse( $http->get( 'https://a.test/' )->ok );
		$this->assertFalse( $http->get( 'https://a.test/' )->ok );
		$this->assertSame( 'ok', $http->get( 'https://a.test/' )->body );
	}

	public function test_queued_answers_go_in_order_then_the_default(): void {
		$http = ( new Fake() )->queue( new Response( true, 201 ), new Response( false, 503 ) );

		$this->assertSame( 201, $http->get( 'https://a.test/' )->status );
		$this->assertSame( 503, $http->get( 'https://a.test/' )->status );
		$this->assertSame( 200, $http->get( 'https://a.test/' )->status );
	}

	public function test_a_route_is_preferred_to_the_queue(): void {
		$http = ( new Fake() )
			->queue( new Response( true, 201 ) )
			->on( 'DELETE', '*', new Response( true, 204 ) );

		$this->assertSame( 204, $http->delete( 'https://a.test/x' )->status );
		$this->assertSame( 201, $http->get( 'https://a.test/x' )->status );
	}

	public function test_a_closure_answer_sees_the_request(): void {
		$http = ( new Fake() )->on( 'POST', '*', fn ( string $method, string $url, ?string $body ): Response => new Response( true, 200, strrev( (string) $body ) ) );

		$this->assertSame( 'cba', $http->post( 'https://a.test/', 'abc' )->body );
	}

	public function test_every_request_is_recorded(): void {
		$http = new Fake();

		$http->post_json( 'https://a.test/hooks', array( 'a' => 1 ), array( 'X-Id' => '9' ) );
		$http->head( 'https://a.test/file' );

		$this->assertSame( array( 'POST', 'HEAD' ), $http->methods() );

		$posted = $http->sent( 'post', 'https://a.test/hooks' );

		$this->assertCount( 1, $posted );
		$this->assertSame( '{"a":1}', $posted[0]['body'] );
		$this->assertSame( '9', $posted[0]['headers']['X-Id'] );
		$this->assertSame( 'application/json', $posted[0]['headers']['Content-Type'] );
	}

	/**
	 * Client's copies used to be built with `new self`, which from a subclass
	 * is the real client — a double asked for a shorter timeout sent real
	 * requests. They are clones now.
	 */
	public function test_configured_copies_are_still_the_fake_and_share_its_log(): void {
		$http = ( new Fake() )->on( 'GET', '*', new Response( true, 207 ) );
		$copy = $http->with_timeout( 1 )->following_redirects()->with_max_bytes( 1 )->with_headers( array( 'X-A' => '1' ) )->without_ssrf();

		$this->assertInstanceOf( Fake::class, $copy );
		$this->assertSame( 207, $copy->get( 'https://a.test/' )->status, 'The script came with it.' );
		$this->assertCount( 1, $http->requests, 'And the original sees what the copy sent.' );
	}
}
