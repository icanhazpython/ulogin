<?php

namespace Ulogin\Backend\Session;

class PhpDefaultSessionStorage
{
    public function gc()
    {
        // Do nothing, leave it completely up to PHP
        return true;
    }
}

?>
