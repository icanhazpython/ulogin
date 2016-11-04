<?php

namespace Ulogin;
use Ulogin\Backend\Auth\PDOLoginBackend;
use Ulogin\Backend\Auth\LDAPLoginBackend;
use Ulogin\Backend\Auth\OpenIDLoginBackend;
use Ulogin\Backend\Auth\SSH2LoginBackend;
use Ulogin\Backend\Auth\DuoLoginBackend;

class Authenticator
{
    public $Backend = null;
    public $LoginCallback = null;
    public $LoginFailCallback = null;

    // This can be checked any time by the caller.
    // NULL if no authentication process was in place,
    // false if there was an authentication attempt but failed,
    // or a valid Uid if authentication succeeded.
    public $AuthResult = null;

    public function __construct($loginCallback = null, $loginFailCallback = null, $backend = null)
    {
        if ($backend == null) {
            $backend = 'Ulogin\Backend\Auth\\' . UL_AUTH_BACKEND;
            $this->Backend = new $backend();
        } else {
            $this->Backend = $backend;
        }
        $this->LoginCallback = $loginCallback;
        $this->LoginFailCallback = $loginFailCallback;

        $this->AuthResult = $this->Backend->AuthResult;
        if ($this->IsAuthSuccess()) {
            $uid = $this->AuthResult;
            $username = $this->Username($uid);
            $this->AuthSuccess($uid, $username);
        } else {
            if ($this->AuthResult === false) {
                $this->AuthFail(null, null);
            }
        }
    }

    private static function ValidateUsername($str)
    {
        // Cap user input to maximum length
        if (strlen($str) > UL_MAX_USERNAME_LENGTH) {

            return false;
        }

        // See if minimum length requirement is met
        if (strlen(trim($str)) < 1) {
            return false;
        }

        if (strlen(UL_USERNAME_CHECK) > 0) {
            return preg_match(UL_USERNAME_CHECK, $str) === 1;
        }

        return true;
    }

    public function IsAuthSuccess()
    {
        return (($this->AuthResult != null) && ($this->AuthResult !== false));
    }

    private function AuthSuccess($uid, $username)
    {
        // Change session id to fight attacks on the session
        SessionManager::sses_regenerate_id(true);

        // Update last login timestamp
        $this->Backend->UpdateLastLoginTime($uid);

        // Log authentication
        Logger::Log('auth-success', $username, Utilities::GetRemoteIP(false));
        Logger::DebugLog("User '$username' successfully authenticated from " . Utilities::GetRemoteIP(false));

        $this->AuthResult = $uid;

        if (is_callable($this->LoginCallback)) {
            $callback = $this->LoginCallback;
            $callback($uid, $username, $this);
        }
    }

    private function AuthFail($uid, $username)
    {
        $this->AuthResult = false;

        // Change session id to fight attacks on the session
        SessionManager::sses_regenerate_id(true);

        // Log authentication attempt
        Logger::Log('auth-fail', $username, Utilities::GetRemoteIP(false));
        Logger::DebugLog("User '$username' failed authentication from " . Utilities::GetRemoteIP(false));

        // Let us check for brute forcing attempts

        // See if the username is being brute forced
        if (($uid !== false) && ($uid != null) && (UL_BF_USER_LOCKOUT > 0)) {
            // Get how many seconds ago did this user log in successfully
            $last_login_rel = Logger::GetUserLastLoginAgo($username);
            if ($last_login_rel === false) {
                $bf_window = UL_BF_WINDOW;
            } else {
                $bf_window = min($last_login_rel, UL_BF_WINDOW);
            }

            $failed_attempts = Logger::GetFrequencyForUser($username, 'auth-fail', $bf_window);
            if ($failed_attempts >= UL_BF_USER_ATTEMPTS) {
                // Okay, we know there have been at least UL_BF_USER_ATTEMPTS unsuccessful login attempts,
                // in the past $bf_window seconds, zero sucessfull logins since then.
                Logger::DebugLog("Blocking user '$username' for " . UL_BF_USER_LOCKOUT . " seconds due to $failed_attempts failed login attempts (max is " . UL_BF_USER_ATTEMPTS . ")");
                $this->Backend->BlockUser($uid, UL_BF_USER_LOCKOUT);
            }
        }

        // See if an IP is brute forcing
        if (UL_BF_IP_LOCKOUT > 0) {
            // Get how many seconds ago did this user log in successfully
            $ip = Utilities::GetRemoteIP(false);
            $last_login_rel = Logger::GetIpLastLoginAgo($ip);
            if ($last_login_rel === false) {
                $bf_window = UL_BF_WINDOW;
            } else {
                $bf_window = min($last_login_rel, UL_BF_WINDOW);
            }

            $failed_attempts = Logger::GetFrequencyForIp($ip, 'auth-fail', $bf_window);
            if ($failed_attempts >= UL_BF_IP_ATTEMPTS) {
                // Okay, we know there have been at least UL_BF_IP_ATTEMPTS unsuccessful login attempts,
                // in the past $bf_window seconds, zero sucessfull logins since then.
                Logger::DebugLog("Blocking IP '$ip' for " . UL_BF_IP_LOCKOUT . " seconds due to $failed_attempts failed login attempts (max is " . UL_BF_IP_ATTEMPTS . ")");
                IpBlocker::SetBlock($ip, UL_BF_IP_LOCKOUT);
            }
        }

        if (is_callable($this->LoginFailCallback)) {
            $callback = $this->LoginFailCallback;
            $callback($uid, $username, $this);
        }
    }

    private function BlockCheck($uid)
    {
        // Check if the IP is blocked
        if (UL_BF_IP_LOCKOUT > 0) {
            $block_expires = IpBlocker::IpBlocked(Utilities::GetRemoteIP(false));
            if ($block_expires == false) {
                Logger::DebugLog("Failure during login, cannot get block status.");
                Utilities::ul_fail('Failure during login, cannot get block status.');
                return false;
            }

            if ($block_expires > date_create('now')) {
                // IP is blocked
                return false;
            }
        }

        // Check if the user is blocked
        if (UL_BF_USER_LOCKOUT > 0) {
            $block_expires = $this->Backend->UserBlocked($uid);
            if ((!is_object($block_expires) || (get_class($block_expires) != 'DateTime'))) {
                Logger::DebugLog("Failure during login, cannot get block status.");
                Utilities::ul_fail('Failure during login, cannot get block status.');
                return false;
            }

            if ($block_expires > date_create('now')) {
                // User is blocked
                return false;
            }
        }

        return true;
    }

    // Given a uid and a password, this function returns the uid,
    // if all of the following conditions are met:
    // - specified user has the specified password
    // - IP or user has not been blocked
    private function Authenticate3($uid, $password)
    {
        if ($uid == false) {
            // No such user
            return false;
        }

        if ($this->BlockCheck($uid) !== true) {
            return false;
        }

        if ($this->Backend->Authenticate($uid, $password) === true) {
            return $uid;
        } else {
            return false;
        }
    }

    // If the specified user has the specified password, logs the user in
    // and returns true. Returns false otherwise.
    // If the user is blocked, the return of this function will be
    // as if the login information was incorrect.
    private function Authenticate2($username, $password)
    {
        $this->AuthResult = null;

        // Validate user input
        if (!self::ValidateUsername($username)) {
            return false;
        }
        if (!Password::IsValid($password)) {
            return false;
        }

        $uid = $this->Backend->Uid($username);
        $this->AuthResult = $this->Authenticate3($uid, $password);

        if ($this->IsAuthSuccess()) {
            $this->AuthSuccess($uid, $username);
        } else {
            $this->AuthFail($uid, $username);
        }

        return $this->AuthResult;
    }

    // If the specified user has the specified password, logs the user in
    // and returns true. Returns false otherwise.
    // If the user is blocked, the return of this function will be
    // as if the login information was incorrect.
    public function Authenticate($username, $password)
    {
        $start = microtime(true);
        $ret = $this->Authenticate2($username, $password);
        $total = microtime(true) - $start;

        if (!$this->IsAuthSuccess() && (UL_LOGIN_DELAY > 0)) {
            // Here we make all false login attempts last the same amount of time
            // to avoid timing attacks on valid usernames.

            $exec_limit = ini_get('max_execution_time');
            set_time_limit(0);

            while ($total < UL_LOGIN_DELAY) {
                $us = (UL_LOGIN_DELAY - $total) * 1000000;

                // Stall next login for a bit.
                // This will considerably slow down brute force attackers.
                usleep($us);

                $total = microtime(true) - $start;
            }

            set_time_limit($exec_limit);
        }

        return $ret;
    }

    // Returns the username corresponding to a user id.
    // Returns false on error.
    public function Username($uid)
    {
        return $this->Backend->Username($uid);
    }

    // Returns the uid corresponding to a username.
    // Returns false on error.
    public function Uid($username = null)
    {
        // Validate user input
        if (!self::ValidateUsername($username)) {
            return false;
        }

        return $this->Backend->Uid($username);
    }

    // Perform actions related to a logout, like disabling remember-me.
    // However, actually logging out is a task of the host application.
    public function Logout($uid)
    {
        $username = $this->Username($uid);
        Logger::Log('logout', $username, Utilities::GetRemoteIP(false));

        $this->SetAutologin($username, false);
    }

    // Creates a new user in the database.
    // Returns true if successful, false if the user already exists or inputs are
    // invalid, NULL on other errors.
    // $profile, if supplied, contains backend-specific data to be inserted, where
    // backend is supposed to simultanously contain login and profile information (eg. LDAP.)
    public function CreateUser($username, $password, $profile = null)
    {
        // Validate user input
        if (!self::ValidateUsername($username)) {
            Logger::DebugLog("User '$username' could not be validated for account creation");
            return false;
        }
        if (!Password::IsValid($password)) {
            Logger::DebugLog("Password for user '$username' could not be validated for account creation");
            return false;
        }

        $ret = $this->Backend->CreateLogin($username, $password, $profile);
        if ($ret !== true) {
            if ($ret == AbstractLoginBackend::ALREADY_EXISTS) {
                return false;
            } else {
                return null;
            }
        }

        Logger::Log('create login', $username, Utilities::GetRemoteIP(false));
        Logger::DebugLog("User '$username' has been created");

        return true;
    }

    // Sets a new password to a user.
    // Returns true if successful, false otherwise.
    public function SetPassword($uid, $password)
    {
        // Needed for logging
        $username = self::Username($uid);
        if ($username === false) {
            Logger::DebugLog("Could not lookup user name for uid '$uid'");
            return false;
        }

        // Validate user input
        if (!Password::IsValid($password)) {
            Logger::DebugLog("Password for user '$username' could not be validated for account creation");
            return false;
        }
        $r = ($this->Backend->SetPassword($uid, $password) === true);
        ($r) ? Logger::DebugLog("Password has been set for '$username'") : Logger::DebugLog("Password could not be set for '$username'");
        return $r;
    }

    // Deletes new user from the database.
    // Returns true if successful, false otherwise.
    public function DeleteUser($uid)
    {
        // Needed for logging
        $username = self::Username($uid);
        if ($username === false) {
            Logger::DebugLog("Could not lookup user name for uid '$uid'");
            return false;
        }

        // Delete user and logout
        $ret = $this->Backend->DeleteLogin($uid);
        if ($ret === true) {
            Logger::Log('delete login', $username, Utilities::GetRemoteIP(false));
        }
        ($ret) ? Logger::DebugLog("Username '$username' has been deleted") : Logger::DebugLog("Username '$username' could not be deleted");
        return $ret === true;
    }

    // Blocks or unblocks a user.
    // Set $block to a positive value to block for that many seconds.
    // Set $block to zero or negative to unblock.
    // Returns true on success, false otherwise.
    public function BlockUser($uid, $block)
    {
        $r = ($this->Backend->BlockUser($uid, $block) === true);
        return $this->Backend->BlockUser($uid, $block) === true;
    }

    // If the user is blocked, returns a DateTime object
    // telling when to unblock the user. If block expired, user is unblocked
    // automatically.
    // If the user is not blocked, returns a DateTime from the past.
    // Returns false on error.
    public function IsUserBlocked($uid)
    {
        return $this->Backend->UserBlocked($uid) == true;
    }

    public function SetAutologin($username, $enable)
    {
        // Set SSL level
        $httpsOnly = Utilities::IsHTTPS();

        // Cookie-name
        $autologin_name = 'AutoLogin';

        if ($enable == true) {
            if (!$this->Backend->IsAutoLoginAllowed()) {
                return false;
            }

            // Validate user input
            if (!self::ValidateUsername($username)) {
                return false;
            }

            // Check whetehr the user exists
            $uid = $this->Uid($username);
            if ($uid === false) {
                return false;
            }

            // Cookie expiry
            $expire = time() + UL_AUTOLOGIN_EXPIRE;

            // We store a nonce in the cookie so that it can only be used once
            $nonce = Nonce::Create("$username-autologin", UL_AUTOLOGIN_EXPIRE, true);

            // HMAC
            // Used to verify that cookie really comes from us
            $hmac = hash_hmac(UL_HMAC_FUNC, "$username:::$nonce", UL_SITE_KEY);

            // Construct contents
            $autologin_data = "$username:::$nonce:::$hmac";

            // Set autologin cookie
            setcookie($autologin_name, $autologin_data, $expire, '/', (UL_DOMAIN === 'localhost') ? '' : UL_DOMAIN,
                $httpsOnly, true);

            Logger::DebugLog("Autologin for '$username' has been set with expiry timestamp of $expire (" . UL_AUTOLOGIN_EXPIRE . " seconds from now)");
        } else {
            // Cookie expiry
            $expire = time() - (3600 * 24 * 365);

            $autologin_data = '';

            // Set autologin cookie
            setcookie($autologin_name, $autologin_data, $expire, '/', (UL_DOMAIN === 'localhost') ? '' : UL_DOMAIN,
                $httpsOnly, true);

            Logger::DebugLog("Autologin for '$username' has been disabled");
        }

        return true;
    }

    public function Autologin()
    {
        if (!$this->Backend->IsAutoLoginAllowed()) {
            return false;
        }

        // Cookie-name
        $autologin_name = 'AutoLogin';

        // Read encrypted cookie
        if (!isset($_COOKIE[$autologin_name])) {
            return false;
        }
        $data = $_COOKIE[$autologin_name];

        // Decrypt cookie data
        $parts = explode(':::', $data);
        $username = $parts[0];
        $nonce = $parts[1];
        $hmac = $parts[2];

        // Check if nonce in cookie is valid
        if (!Nonce::Verify("$username-autologin", $nonce)) {
            $this->SetAutologin($username, false);
            return false;
        }

        // Check if cookie was set by us.
        if ($hmac != hash_hmac(UL_HMAC_FUNC, "$username:::$nonce", UL_SITE_KEY)) {
            $this->SetAutologin($username, false);
            $this->AuthFail(null, $username);
            return false;
        }

        // Get Uid and see if user exists. See if user is still valid.
        $uid = $this->Uid($username);
        if ($uid === false) {
            $this->SetAutologin($username, false);
            $this->AuthFail(null, $username);
            return false;
        }

        // Check if there is a block that applies to us
        if ($this->BlockCheck($uid) !== true) {
            $this->SetAutologin($username, false);
            $this->AuthFail($uid, $username);
            return false;
        }

        // Everything seems alright. Log user in and set new autologin cookie.
        $this->AuthSuccess($uid, $username);
        $this->SetAutologin($username, true);
        Logger::DebugLog("Autologin for '$username' successful");
        return $uid;
    }
}

?>
