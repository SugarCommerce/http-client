<?php
http_response_code( (int) ( $_GET['code'] ?? 200 ) );
echo 'status body';
