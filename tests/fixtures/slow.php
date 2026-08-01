<?php
sleep( (int) ( $_GET['seconds'] ?? 1 ) );
echo 'slow';
