<?php
header( 'Content-Type: text/plain' );
echo str_repeat( 'x', ( (int) ( $_GET['kb'] ?? 1 ) ) * 1024 );
