<?php
header( 'Content-Type: application/json' );
echo json_encode( array_change_key_case( getallheaders(), CASE_LOWER ) );
