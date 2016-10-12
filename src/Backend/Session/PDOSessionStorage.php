<?php

namespace Ulogin\Backend\Session;
use Ulogin\Backend\Auth\PDOBackend\Database;
use Ulogin\Utilities;
use \DateTime;

class PDOSessionStorage
{
    private $lifetime;
    private $max_execution_time;
    private $lock_acquired = array();

    private function Lock($id)
    {
        if (isset($this->lock_acquired[$id])) {
            return true;
        }

        $session_expires = Utilities::date_seconds_add(new DateTime(), $this->lifetime)->format(UL_DATETIME_FORMAT);
        $lock_expires = Utilities::date_seconds_add(new DateTime(),
            $this->max_execution_time)->format(UL_DATETIME_FORMAT);

        // Try inserting a new session in every case, in a locked state
        $stmt = Database::Prepare(
            'session',
            "INSERT INTO ul_sessions (id, data, session_expires, lock_expires) VALUES (?, '', ?, ?)"
        );
        if (!Database::BindExec(
            $stmt,
            null,        // output
            array(        // input
                &$id,
                'str',
                &$session_expires,
                'str',
                &$lock_expires,
                'str'
            )
        )
        ) {
            if (Database::ErrorCode() == '23000') {
                // The insert failed because of a duplicate key, meaning the session
                // already exists. So try to acquire a lock.

                // Acquire lock
                while (!isset($this->lock_acquired[$id])) {
                    $now = Utilities::nowstring();
                    $session_expires = Utilities::date_seconds_add(new DateTime(),
                        $this->lifetime)->format(UL_DATETIME_FORMAT);
                    $lock_expires = Utilities::date_seconds_add(new DateTime(),
                        $this->max_execution_time)->format(UL_DATETIME_FORMAT);
                    $stmt = Database::Prepare('session',
                        'UPDATE ul_sessions SET session_expires=?, lock_expires=? WHERE id=? AND lock_expires<?');
                    if (!Database::BindExec(
                        $stmt,
                        null,        // output
                        array(        // input
                            &$session_expires,
                            'str',
                            &$lock_expires,
                            'str',
                            &$id,
                            'str',
                            &$now,
                            'str'
                        )
                    )
                    ) {
                        Database::Fail('Session management error.');
                        return false;
                    }

                    if ($stmt->rowCount() > 0) {
                        $this->lock_acquired[$id] = true;
                    } else {
                        usleep(100000);
                    }    // 100ms
                }
                // Okay, we have a lock and theoretically an exclusive access
            } else {
                // No, it wasn't a duplicate record... let's fail miserably.
                Database::Fail('Session management error.');
                return false;
            }
        } else {
            $this->lock_acquired[$id] = true;
        }

        return true;
    }

    private function Unlock($id)
    {
        // Since inside a lock we have exclusive access to the record, we can just unlock it without
        // any additional checks.

        $past = date_format(date_create('1000 years ago'), UL_DATETIME_FORMAT);
        $stmt = Database::Prepare('session', 'UPDATE ul_sessions SET lock_expires=? WHERE id=?');
        if (!Database::BindExec(
            $stmt,
            null,        // output
            array(        // input
                &$past,
                'str',
                &$id,
                'str'
            )
        )
        ) {
            Database::Fail('Session management error.');
            return false;
        }

        unset($this->lock_acquired[$id]);

        return true;
    }

    public function __construct()
    {
        // Get default lifetime of sessions, in seconds
        $this->lifetime = get_cfg_var('session.gc_maxlifetime');
        $this->max_execution_time = ini_get('max_execution_time');

        // In newer PHP versions, objects are destroyed before
        // session data is written, so normally we wouldn't be able to
        // use $db_link when our write() method is called at the end of a script.
        // Registering session_write_close() as a shutdown
        // function will call write() before object destruction, which
        // takes care of our problem.
        register_shutdown_function('session_write_close');

        // Register session storage handlers
        session_set_save_handler(
            array(&$this, 'open'),
            array(&$this, 'close'),
            array(&$this, 'read'),
            array(&$this, 'write'),
            array(&$this, 'destroy'),
            array(&$this, 'gc')
        );
    }

    public function __destruct()
    {
        $this->close();
    }

    public function open($save_path, $id)
    {
        return true;
    }

    public function close()
    {
        // Unlock all records owned by us
        $ids = array_keys($this->lock_acquired);
        foreach ($ids as $id) {
            $this->Unlock($id);
        }

        return true;
    }

    public function read($id)
    {
        if ($this->Lock($id) != true) {
            return false;
        }

        // Even if we don't have data, we need to return an empty string
        $data = '';

        // Read database
        $now = Utilities::nowstring();
        $stmt = Database::Prepare('session', 'SELECT data FROM ul_sessions WHERE id=? AND session_expires>?');
        if (!Database::BindExec(
            $stmt,
            array(        // output
                &$data,
                'lob'
            ),
            array(        // input
                &$id,
                'str',
                &$now,
                'str'
            )
        )
        ) {
            Database::Fail('Session management error.');
            return false;
        }

        if (!Database::Fetch($stmt)) {
            Utilities::ul_fail('Error reading session.');
            return false;
        }

        return $data;
    }

    public function write($id, $data)
    {
        if ($this->Lock($id) != true) {
            return false;
        }

        $stmt = Database::Prepare(
            'session',
            'UPDATE ul_sessions SET data=? WHERE id=?'
        );
        if (!Database::BindExec(
            $stmt,
            null,        // output
            array(        // input
                &$data,
                'lob',
                &$id,
                'str'
            )
        )
        ) {
            Database::Fail('Session management error.');
            return false;
        }
    }

    public function destroy($id)
    {
        $stmt = Database::Prepare('session', 'DELETE FROM ul_sessions WHERE id=?');
        $ret = Database::BindExec(
            $stmt,
            null,        // output
            array(        // input
                &$id,
                'str'
            )
        );

        return $ret;
    }

    public function gc()
    {
        $now = Utilities::nowstring();

        // Delete old sessions
        $stmt = Database::Prepare('session', 'DELETE FROM ul_sessions WHERE session_expires<=?');
        Database::BindExec(
            $stmt,
            null,        // output
            array(        // input
                &$now,
                'str'
            )
        );

        return true;
    }
}

?>
