<?php
declare( strict_types=1 );
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../../bench-lib.php';

use SugarCommerce\HttpClient\{Client, SsrfPolicy};

$policy = new SsrfPolicy();

echo "http-client (policy only — no network)\n";
bench( 'is_public_ip (v4)', 200000, static fn() => SsrfPolicy::is_public_ip( '93.184.216.34' ) );
bench( 'is_public_ip (v6)', 200000, static fn() => SsrfPolicy::is_public_ip( '2606:4700:4700::1111' ) );
bench( 'is_public_ip (reject)', 200000, static fn() => SsrfPolicy::is_public_ip( '10.0.0.1' ) );
bench( 'validate (ip literal)', 100000, static fn() => $policy->validate( 'http://93.184.216.34/path' ) );
bench( 'validate (rejected scheme)', 200000, static fn() => $policy->validate( 'file:///etc/passwd' ) );
bench( 'normalize_headers', 200000, static fn() => Client::normalize_headers( array( 'Content-Type' => 'application/json', 'X-A' => 'b' ) ) );
bench_footer();
