<?php

require 'vendor/autoload.php';

use Ulogin\Logger;
use Ulogin\Backend\PDO\NonceStore;
use Ulogin\Backend\Session\PDOSessionStorage;
use Ulogin\Backend\Session\PhpDefaultSessionStorage;

// Limit size of log by cleaning it
Logger::Clean();

// Clean up expired sessions of the default storage engine set in the configuration
$SessionStoreClass = 'Ulogin\Backend\Session\\' . UL_SESSION_BACKEND;
$SessionStore = new $SessionStoreClass();
$SessionStore->gc();

// Remove expired nonces
NonceStore::Clean();

?>
