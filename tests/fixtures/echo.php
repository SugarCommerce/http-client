<?php
header( 'Content-Type: text/plain' );
echo 'method=' . $_SERVER['REQUEST_METHOD'] . "\n";
echo 'query=' . ( $_SERVER['QUERY_STRING'] ?? '' ) . "\n";
foreach ( $_SERVER as $k => $v ) {
	if ( str_starts_with( $k, 'HTTP_X_' ) || 'CONTENT_TYPE' === $k ) {
		echo strtolower( $k ) . '=' . $v . "\n";
	}
}
echo "body=" . file_get_contents( 'php://input' ) . "\n";
