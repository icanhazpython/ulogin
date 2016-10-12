<?php

namespace Ulogin\Backend\Auth\PDOBackend;
use Ulogin\Utilities;
use \DateTime;

class NonceStore
{
    public static function Store($action, $code, $expire)
    {
        // Insert new nonce into database
        $nonce_expires = Utilities::date_seconds_add(new DateTime(), $expire)->format(UL_DATETIME_FORMAT);
        $stmt = Database::Prepare('session', 'INSERT INTO ul_nonces (code, action, nonce_expires) VALUES (?, ?, ?)');
        if (!Database::BindExec(
            $stmt,
            null,        // output
            array(        // input
                &$code,
                'str',
                &$action,
                'str',
                &$nonce_expires,
                'str'
            )
        )
        ) {
            if (Database::ErrorCode() == '23000') {
                // Probably, the action already exists
                $stmt = Database::Prepare('session', 'UPDATE ul_nonces SET code=?, nonce_expires=? WHERE action=?');
                if (!Database::BindExec(
                    $stmt,
                    null,        // output
                    array(        // input
                        &$code,
                        'str',
                        &$nonce_expires,
                        'str',
                        &$action,
                        'str'
                    )
                )
                ) {
                    Database::Fail();
                    return false;
                }
            } else {
                // No, it wasn't a duplicate user... let's fail miserably.
                Database::Fail();
                return false;
            }
        }

        return true;
    }


    public static function Verify($action, $code)
    {
        // See if there is a nonce like the one requested
        $exists = 0;
        $now = Utilities::nowstring();
        $stmt = Database::Prepare('session',
            'SELECT COUNT(*) FROM ul_nonces WHERE code=? AND action=? AND nonce_expires>?');
        if (!Database::BindExec(
            $stmt,
            array(        // output
                &$exists,
                'int'
            ),
            array(        // input
                &$code,
                'str',
                &$action,
                'str',
                &$now,
                'str'
            )
        )
        ) {
            Database::Fail();
            return false;
        }

        Database::Fetch($stmt);

        if ($exists > 0) {
            // We have found a nonce, invalidate it
            $stmt = Database::Prepare('session', 'DELETE FROM ul_nonces WHERE code=? AND action=?');
            if (!Database::BindExec(
                $stmt,
                null,        // output
                array(        // input
                    &$code,
                    'str',
                    &$action,
                    'str'
                )
            )
            ) {
                Database::Fail();
            }

            return true;
        } else {
            // Invalid nonce
            return false;
        }
    }


    public static function Exists($action)
    {
        // See if there is a nonce like the one requested
        $exists = 0;
        $stmt = Database::Prepare('session', 'SELECT COUNT(*) FROM ul_nonces WHERE action=?');
        if (!Database::BindExec(
            $stmt,
            array(        // output
                &$exists,
                'int'
            ),
            array(        // input
                &$action,
                'str'
            )
        )
        ) {
            Database::Fail();
            return false;
        }

        Database::Fetch($stmt);

        return ($exists > 0);
    }

    public static function Clean()
    {
        // We have found a nonce, invalidate it
        $now = Utilities::nowstring();
        $stmt = Database::Prepare('session', 'DELETE FROM ul_nonces WHERE nonce_expires<?');
        if (!Database::BindExec(
            $stmt,
            null,        // output
            array(        // input
                &$now,
                'str'
            )
        )
        ) {
            Database::Fail();
            return false;
        }

        return true;
    }
}

?>
