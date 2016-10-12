<?php

namespace Ulogin;
use Ulogin\Backend\Auth\PDOBackend\Database;
use \DateTime;

class IpBlocker
{
    // Blocks or unblocks an IP.
    // Set $block to a positive value to block for that many seconds.
    // Set $block to zero or negative to unblock.
    // Returns true on success, false otherwise.
    public static function SetBlock($ip, $block)
    {
        $stmt = null;
        $query_ret = true;

        if ($block > 0) {
            // Insert new IP, or extend block if it already exists
            $block_expires = Utilities::date_seconds_add(new DateTime(), $block)->format(UL_DATETIME_FORMAT);
            $stmt = Database::Prepare('log', 'INSERT INTO ul_blocked_ips (ip, block_expires) VALUES (?, ?)');
            $query_ret = Database::BindExec(
                $stmt,
                null,        // output
                array(        // input
                    &$ip,
                    'str',
                    &$block_expires,
                    'str'
                )
            );

            if (!$query_ret && (Database::ErrorCode() == '23000')) {
                // IP already in the list, so update
                $stmt = Database::Prepare('log', 'UPDATE ul_blocked_ips SET block_expires=? WHERE ip=?');
                $query_ret = Database::BindExec(
                    $stmt,
                    null,        // output
                    array(        // input
                        &$block_expires,
                        'str',
                        &$ip,
                        'str'
                    )
                );
            }
        } else {
            $stmt = Database::Prepare('log', 'DELETE FROM ul_blocked_ips WHERE ip=?');
            $query_ret = Database::BindExec(
                $stmt,
                null,        // output
                array(        // input
                    &$ip,
                    'str'
                )
            );
        }

        if (!$query_ret || ($stmt->rowCount() == 0)) {
            Database::Fail();
            return false;
        }

        return true;
    }

    // If the ip is blocked, returns a DateTime object
    // telling when to unblock the ip. If block expired,
    // ip is unblocked automatically.
    // If the ip is not blocked, returns a DateTime from the past.
    // Returns false on error.
    public static function IpBlocked($ip)
    {
        $block_expires = null;

        $stmt = Database::Prepare('log', 'SELECT block_expires FROM ul_blocked_ips WHERE ip=?');
        if (!Database::BindExec(
            $stmt,
            array(        // output
                &$block_expires,
                'str'
            ),
            array(        // input
                &$ip,
                'str'
            )
        )
        ) {
            Database::Fail();
            return false;
        }

        if (Database::Fetch($stmt)) {
            $block_expires = new DateTime($block_expires);

            if ($block_expires <= date_create('now')) {
                self::SetBlock($ip, 0);
            }
        } else {
            $block_expires = new DateTime('1000 years ago');
        }
        return $block_expires;
    }
}

?>
