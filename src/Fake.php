<?php
/**
 * A client that answers from a script, for tests.
 *
 * @package   SugarCommerce\HttpClient
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.2.0
 */

declare( strict_types=1 );

namespace SugarCommerce\HttpClient;

/**
 * Class Fake
 *
 * Stands in for Client wherever code takes one, answers without touching the
 * network, and remembers every request it was given.
 *
 *   $http = ( new Fake() )
 *       ->on( 'GET', 'https://api.example.com/things/*', new Response( true, 200, '{"id":1}' ) )
 *       ->queue( Response::failure( 'timeout' ) );
 *
 *   $http->sent( 'POST' );   // what was posted, in order
 *
 * A request is answered by the first route that matches it, then by the next
 * queued answer, then by the default — a bare 200 unless the fake was made
 * with strict(), where an unscripted request fails so a test cannot pass on
 * the strength of a call it never meant to make.
 *
 * Every consumer used to write its own double, and each one learned the same
 * lesson separately: a readonly class can only record into an object it
 * already holds. Its copies — with_timeout() and the rest — are clones, so
 * they are this fake too, and record into the same log.
 *
 * @since 1.2.0
 */
final readonly class Fake extends Client {

	/**
	 * Bytes per chunk when a scripted body is played into a stream() sink.
	 */
	public const int CHUNK = 8192;

	/**
	 * Every request, in order.
	 *
	 * @var \ArrayObject<int, array{method: string, url: string, body: string|null, headers: array<string, string>}>
	 */
	public \ArrayObject $requests;

	/**
	 * Routes, each `[method, url pattern, answer, uses left]`.
	 *
	 * Uses left is null for a route that never runs out.
	 *
	 * @var \ArrayObject<int, array{0: string, 1: string, 2: Response|\Closure, 3: int|null}>
	 */
	private \ArrayObject $routes;

	/**
	 * Answers for the next unrouted requests, first first.
	 *
	 * @var \ArrayObject<int, Response>
	 */
	private \ArrayObject $queued;

	/**
	 * @since 1.2.0
	 *
	 * @param Response|null $otherwise The answer when nothing is scripted.
	 *                                 Null fails the request instead.
	 */
	public function __construct( private ?Response $otherwise = new Response( true, 200 ) ) {
		parent::__construct( ssrf: null );

		$this->requests = new \ArrayObject();
		$this->routes   = new \ArrayObject();
		$this->queued   = new \ArrayObject();
	}

	/**
	 * A fake that fails any request nobody scripted.
	 *
	 * @since 1.2.0
	 *
	 * @return self
	 */
	public static function strict(): self {
		return new self( null );
	}

	/* ─── Scripting ─────────────────────────────────────────────────── */

	/**
	 * Answer matching requests.
	 *
	 * The pattern is a glob over the whole URL, query string included, so
	 * `https://api.example.com/v1/charges*` matches any query on that path.
	 * A closure answer is called with `(method, url, body, headers)` and
	 * returns the Response, for an answer that depends on what was sent.
	 *
	 * @since 1.2.0
	 *
	 * @param string            $method HTTP verb, or '*' for any.
	 * @param string            $url    URL glob.
	 * @param Response|\Closure $answer The answer, or what builds it.
	 * @param int|null          $times  How many requests it answers before
	 *                                  it stops matching. Null for all.
	 *
	 * @return self
	 */
	public function on( string $method, string $url, Response|\Closure $answer, ?int $times = null ): self {
		$this->routes[] = array( strtoupper( $method ), $url, $answer, $times );

		return $this;
	}

	/**
	 * Answer the next unrouted requests with these, in order.
	 *
	 * @since 1.2.0
	 *
	 * @param Response ...$answers Answers.
	 *
	 * @return self
	 */
	public function queue( Response ...$answers ): self {
		foreach ( $answers as $answer ) {
			$this->queued[] = $answer;
		}

		return $this;
	}

	/* ─── Inspection ────────────────────────────────────────────────── */

	/**
	 * The requests that match, in order.
	 *
	 * @since 1.2.0
	 *
	 * @param string $method HTTP verb, or '*' for any.
	 * @param string $url    URL glob.
	 *
	 * @return array<int, array{method: string, url: string, body: string|null, headers: array<string, string>}>
	 */
	public function sent( string $method = '*', string $url = '*' ): array {
		return array_values( array_filter(
			$this->requests->getArrayCopy(),
			fn ( array $request ): bool => self::matches( strtoupper( $method ), $url, $request['method'], $request['url'] )
		) );
	}

	/**
	 * The verbs used, in order.
	 *
	 * @since 1.2.0
	 *
	 * @return string[]
	 */
	public function methods(): array {
		return array_column( $this->requests->getArrayCopy(), 'method' );
	}

	/* ─── Engine ────────────────────────────────────────────────────── */

	/**
	 * Record the request and answer it from the script.
	 *
	 * Every verb on Client comes through here, so overriding this one method
	 * is enough to fake them all.
	 *
	 * @since 1.2.0
	 *
	 * @param string                $method  HTTP verb.
	 * @param string                $url     URL.
	 * @param string|null           $body    Request body.
	 * @param array<string, string> $headers Extra headers.
	 *
	 * @return Response
	 */
	#[\Override]
	public function request( string $method, string $url, ?string $body = null, array $headers = array() ): Response {
		$method = strtoupper( $method );

		$this->requests[] = array( 'method' => $method, 'url' => $url, 'body' => $body, 'headers' => $headers );

		$answer = $this->route( $method, $url ) ?? $this->next() ?? $this->otherwise;

		if ( $answer instanceof \Closure ) {
			$answer = $answer( $method, $url, $body, $headers );
		}

		return $answer ?? Response::failure( 'unscripted: ' . $method . ' ' . $url );
	}

	/**
	 * Record a streamed GET and play the scripted body into the sink.
	 *
	 * Answered from the same script as a GET, and recorded as one. Only a
	 * 2xx body is played, in chunks, the way Client passes one on; anything
	 * else comes back as it was scripted and the sink is never called — so a
	 * test of an error path sees exactly what production would.
	 *
	 * @since 1.4.0
	 *
	 * @param string                $url     URL.
	 * @param \Closure              $sink    Receives each chunk of a 2xx body.
	 * @param array<string, string> $headers Extra headers.
	 *
	 * @return Response The scripted answer, with the body taken out when it
	 *                  went to the sink.
	 */
	#[\Override]
	public function stream( string $url, \Closure $sink, array $headers = array() ): Response {
		$answer = $this->request( 'GET', $url, null, $headers );

		if ( ! $answer->ok ) {
			return $answer;
		}

		foreach ( '' === $answer->body ? array() : str_split( $answer->body, self::CHUNK ) as $chunk ) {
			$sink( $chunk );
		}

		return new Response( true, $answer->status, '', $answer->content_type, '', $answer->headers, $answer->duration, $answer->final_url );
	}

	/**
	 * The first route that matches and has uses left, spending one.
	 *
	 * @param string $method HTTP verb, uppercase.
	 * @param string $url    URL.
	 *
	 * @return Response|\Closure|null
	 */
	private function route( string $method, string $url ): Response|\Closure|null {
		foreach ( $this->routes as $index => [ $want_method, $pattern, $answer, $left ] ) {
			if ( 0 === $left || ! self::matches( $want_method, $pattern, $method, $url ) ) {
				continue;
			}

			if ( null !== $left ) {
				$this->routes[ $index ] = array( $want_method, $pattern, $answer, $left - 1 );
			}

			return $answer;
		}

		return null;
	}

	/**
	 * Take the next queued answer.
	 *
	 * @return Response|null
	 */
	private function next(): ?Response {
		$queued = $this->queued->getArrayCopy();
		$answer = array_shift( $queued );

		$this->queued->exchangeArray( $queued );

		return $answer;
	}

	/**
	 * Whether a request fits a verb and a URL glob.
	 *
	 * @param string $want_method Verb wanted, or '*'.
	 * @param string $pattern     URL glob.
	 * @param string $method      Verb used.
	 * @param string $url         URL used.
	 *
	 * @return bool
	 */
	private static function matches( string $want_method, string $pattern, string $method, string $url ): bool {
		// FNM_NOESCAPE: a URL is full of characters that are not glob
		// escapes, and a backslash in one should mean a backslash.
		return ( '*' === $want_method || $want_method === $method ) && fnmatch( $pattern, $url, FNM_NOESCAPE );
	}
}
