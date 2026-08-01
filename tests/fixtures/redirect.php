<?php
header( 'Location: ' . ( $_GET['to'] ?? '/json.php' ), true, 302 );
