<?php
// A few bytes with a pause between each: slower than the client's timeout in
// total, but never silent for that long.
header( 'Content-Type: text/plain' );

while ( ob_get_level() > 0 ) {
	ob_end_flush();
}

$count = (int) ( $_GET['bytes'] ?? 6 );
$pause = (int) ( $_GET['ms'] ?? 400 ) * 1000;

for ( $i = 0; $i < $count; $i++ ) {
	if ( $i > 0 ) {
		usleep( $pause );
	}

	echo chr( 97 + $i );
	flush();
}
