<?php
/*
Code in this file is based on:
http://thinkvitamin.com/code/how-to-create-bulletproof-sessions/

Copyright (c) 2009, Robert Hafner
Copyright (c) 2011, Károly Pados
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
      disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
      following disclaimer in the documentation and/or other materials provided with the distribution.
    * The names of the contributors may not be used to endorse or promote
      products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * This SessionManager starts starts the php session (regardless of which handler is set) and secures it by locking down
 * the cookie, restricting the session to a specific host and browser, and regenerating the ID.
 *
 */

namespace Ulogin;
use Ulogin\Backend\Session\PDOSessionStorage;
use Ulogin\Backend\Session\PhpDefaultSessionStorage;

class SessionManager
{
    /**
     * AOL users may switch IP addresses from one proxy to another.
     *
     * @link http://webmaster.info.aol.com/proxyinfo.html
     * @var array
     */
    private static $aolProxies = array(
        '64.12.9',
        '149.174',
        '152.163',
        '195.93.',
        '198.81.',
        '202.67.',
        '205.188',
        '207.200'
    );

    /**
     * Object to take care of reading/writing session data.
     */
    private static $SessionStore = null;

    /**
     * Did we have a security problem while starting up the session?
     * This will be set to true upon a possible security issue,
     * but it needs to be reset to false by external code.
     */
    public static $TrustInvalidated = false;

    /**
     * Tells if there is a secure session currently started.
     */
    public static $SessionRunning = false;

    /**
     * Set properties for a PHP session and start it up.
     */
    private static function _sessionStart()
    {
        self::EnsureStorage();

        // Set session cookie options
        session_name('SSESID');
        session_set_cookie_params(0, '/', (UL_DOMAIN === 'localhost') ? '' : UL_DOMAIN, Utilities::IsHTTPS(), true);
        session_start();
    }

    private static function tryFingerprint()
    {
        static $fp = null;
        if ($fp == null) {
            $fp = array();
            $fp['IPaddress'] = UL_SESSION_CHECK_IP ? Utilities::GetRemoteIP(false) : '';
            $fp['hostDomain'] = !UL_SESSION_CHECK_REFERER || empty($_SERVER['HTTP_REFERER']) ? '' : parse_url($_SERVER['HTTP_REFERER'],
                PHP_URL_HOST);
            $fp['userAgent'] = empty($_SERVER['HTTP_USER_AGENT']) ? '' : $_SERVER['HTTP_USER_AGENT'];
        }
        return $fp;
    }

    /**
     * This function starts or continues a secure session.
     * Takes care of session validation, expiry handling and hijacking detection.
     * Returns true if everything went well.
     * Returns false if the previous session was invalid for any reason.
     * If false is returned, then no new session has been started, but it can be called again
     * to start a new session.
     *
     * @param string $sid_regen_prob Keep the session id changing throughout the session, with this probability (0-100)
     */
    public static function sessionStart($sid_regen_prob)
    {
        // Used as a temporary storage to be able to keep some session data
        // even when the session gets invalidated.
        static $TmpNonSensitiveData = null;

        // Start a PHP session. After this call session data is available.
        self::_sessionStart();

        if (self::isNewSession())    // Are we just starting a new session?
        {
            Logger::DebugLog('Starting a new uLogin session.', 0);

            // Reset session data and regenerate id
            self::changeSessionId(true, true);
            $_SESSION = array();
            $_SESSION['sses'] = self::tryFingerprint();

            // Play back data we want kept from a previously invalidated session
            if ($TmpNonSensitiveData != null) {
                $_SESSION['nonsensitive'] = $TmpNonSensitiveData;
            }
        } // Make sure the session hasn't expired or been hijacked, and destroy it if it has
        else {
            if (self::validateSession()) {
                Logger::DebugLog('Continuing an existing uLogin session.', 0);

                // Give a chance of the session id changing on any request
                if (rand(1, 100) <= $sid_regen_prob) {
                    Logger::DebugLog('Probability for automatic SID change reached.', 0);
                    self::changeSessionId(true, false);
                }
            } else {
                Logger::DebugLog('Session validation failed.', 4);

                // Keep a small part of the session data even in case the session gets invalidated.
                if (isset($_SESSION['nonsensitive'])) {
                    $TmpNonSensitiveData = $_SESSION['nonsensitive'];
                }

                // Destroy previous session
                self::$TrustInvalidated = true;
                self::sessionDestroy();
                return false;
            }
        }

        self::sessionSetExpiry();
        self::updateTokenCookie();
        self::$SessionRunning = true;

        return true;
    }

    private static function updateTokenCookie()
    {
        if (!UL_PREVENT_REPLAY) {
            return;
        }

        $cookieName = 'SSESTOKEN';
        $cookieData = Nonce::Create('ulSessionToken', UL_SESSION_EXPIRE);

        setcookie($cookieName, $cookieData, 0, '/', (UL_DOMAIN === 'localhost') ? '' : UL_DOMAIN, Utilities::IsHTTPS(),
            true);
    }

    private static function verifyTokenCookie()
    {
        if (!UL_PREVENT_REPLAY) {
            return true;
        }

        $cookieName = 'SSESTOKEN';

        if (!isset($_COOKIE[$cookieName])) {
            return false;
        }
        $cookieData = $_COOKIE[$cookieName];

        return Nonce::Verify('ulSessionToken', $cookieData);
    }

    private static function sessionSetExpiry()
    {
        // Set session expiry
        if (!defined('UL_SESSION_EXPIRE')) {    // If nothing is set, expire in 20 minutes
            $_SESSION['sses']['EXPIRES'] = time() + 1200;
        } else {
            if (UL_SESSION_EXPIRE < 0) {
                // If negative, do not expire
                unset($_SESSION['sses']['EXPIRES']);
            } else {
                // Set expiry
                $_SESSION['sses']['EXPIRES'] = time() + UL_SESSION_EXPIRE;
            }
        }
    }

    public static function sessionDestroy()
    {
        Logger::DebugLog('Destroying session data.', 1);

        $_SESSION = array();
        setcookie(session_name(), '', time() - 42000, '/', (UL_DOMAIN === 'localhost') ? '' : UL_DOMAIN,
            Utilities::IsHTTPS(), true);
        session_destroy();
        self::$SessionStore = null;
        self::$SessionRunning = false;
    }

    /**
     * This function regenerates a new ID and invalidates the old session. This should be called whenever permission
     * levels for a user change.
     */
    public static function changeSessionId($delete_old_session = false, $delete_old_immediately = true)
    {
        Logger::DebugLog('Changing session id.', 1);

        // If this session is obsolete it means there is already a new id
        if (@$_SESSION['sses']['OBSOLETE'] == true) {
            return;
        }

        if ($delete_old_session) {
            // Set current session to expire in 10 seconds
            $_SESSION['sses']['OBSOLETE'] = true;
            $_SESSION['sses']['EXPIRES'] = time() + 10;
        }

        // Create new session without destroying the old one
        session_regenerate_id($delete_old_immediately);

        // Grab current session ID and close both sessions to allow other scripts to use them
        $newSession = session_id();
        self::sessionWriteClose();

        // Set session ID to the new one, and start it back up again
        session_id($newSession);
        self::_sessionStart();

        // Now we unset the obsolete and expiration values for the session we want to keep
        unset($_SESSION['sses']['OBSOLETE']);
        self::sessionSetExpiry();
    }

    /**
     * This function is used to see if a session has expired or not.
     *
     * @return bool
     */
    private static function validateSession()
    {
        if (isset($_SESSION['sses']['OBSOLETE']) && !isset($_SESSION['sses']['EXPIRES'])) {
            Logger::DebugLog('uLogin session expired.', 3);
            return false;
        }

        if (isset($_SESSION['sses']['EXPIRES']) && ($_SESSION['sses']['EXPIRES'] < time())) {
            Logger::DebugLog('uLogin session expired.', 3);
            return false;
        }

        if (!self::preventHijacking()) {
            // ... details logged in preventHijacking()
            return false;
        }

        return true;
    }

    /**
     * Are we starting a completely new session or are we trying to continue from a previous page?
     *
     * @return bool
     */
    private static function isNewSession()
    {
        if (!isset($_SESSION['sses'])) {
            return true;
        }

        $sses = $_SESSION['sses'];

        if (!isset($sses['IPaddress']) || !isset($sses['userAgent']) || !isset($sses['hostDomain'])) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * This function checks to make sure a session exists and is coming from the proper host. On new visits and hacking
     * attempts this function will return false.
     *
     * @return bool
     */
    private static function preventHijacking()
    {
        $fp = self::tryFingerprint();
        $sses = $_SESSION['sses'];

        // Check for changed user agent, but make special exception for IE
        if ($sses['userAgent'] != $fp['userAgent']
            && !((strpos($sses['userAgent'], 'Trident') !== false) && (strpos($fp['userAgent'], 'Trident') !== false))
        ) {
            Logger::DebugLog('User agent mismatch.', 3);
            return false;
        }

        // Check for changed referrer domain
        if (UL_SESSION_CHECK_REFERER) {
            if (!empty($sses['hostDomain']) && ($sses['hostDomain'] != $fp['hostDomain'])) {
                Logger::DebugLog('HTTP_REFERER mismatch.', 3);
                return false;
            }
        }

        // Check for changed IP, but take proxies into consideration
        if (UL_SESSION_CHECK_IP) {
            $sessionIpSegment = substr($sses['IPaddress'], 0, 7);
            $remoteIpSegment = substr($fp['IPaddress'], 0, 7);
            if ($sses['IPaddress'] != $fp['IPaddress']
                && !(in_array($sessionIpSegment, self::$aolProxies) && in_array($remoteIpSegment, self::$aolProxies))
            ) {
                Logger::DebugLog('IP mismatch.', 3);
                return false;
            }
        }

        // Check for secret token
        if (!self::verifyTokenCookie()) {
            Logger::DebugLog('Session token mismatch.', 3);
            return false;
        }

        return true;
    }

    public static function sessionWriteClose()
    {
        session_write_close();
        self::$SessionStore = null;
        self::$SessionRunning = false;
    }

    private static function EnsureStorage()
    {
        if (self::$SessionStore == null) {
            $storageClass = 'Ulogin\Backend\Session\\' . UL_SESSION_BACKEND;
            self::$SessionStore = new $storageClass();
        }
    }

    // Use instead of session_destroy() to destroy a secure session that has been
    // started with sses_start().
    public static function sses_destroy()
    {
        Logger::DebugLog('Session erase requested by host.', 0);
        self::sessionDestroy();
    }

    // Use instead of session_start() to start a secure session.
    public static function sses_start($sid_regen_prob = UL_SESSION_REGEN_PROB)
    {
        Logger::DebugLog('Session start requested by host.', 0);
        if ($_SESSION !== null) {
          Logger::DebugLog('Session appears to have already been started. This may cause loss of session.', 5);
          throw new \Exception("Session appears to have already been started. This may cause loss of session.");
        }
        if (!self::sessionStart($sid_regen_prob)) {
            // self::sessionStart does not start a new session
            // if it invalidated an old one. So we call it one more time
            // to actually try to start a new session.
            if (!(self::sessionStart($sid_regen_prob))) {
                Logger::DebugLog('Cannot start uLogin session.', 5);
                Utilities::ul_fail('Cannot start session.');
                return false;
            }
            return true;
        } else {
            self::$TrustInvalidated = false;
        }

        return true;
    }

    // Use instead of session_regenerate_id() to change the session
    // identifier. Call if user privileges change.
    public static function sses_regenerate_id($delete_old_session = false)
    {
        Logger::DebugLog('New session id requested by host.', 0);
        return self::changeSessionId($delete_old_session, true);
    }

    // Use instead of session_write_close().
    public static function sses_write_close()
    {
        Logger::DebugLog('Session close requested by host.');
        self::sessionWriteClose();
    }

    // Are we inside a secure session? Returns a boolean.
    public static function sses_running()
    {
        return self::$SessionRunning;
    }

    // Returns a boolean value that indicates if the previous session
    // was continued successfully (false), or if it has been invalidated
    // and restarted to maintain security (true). A return value of true
    // means that the user needs to be re-authenticated.
    public static function sses_invalidated()
    {
        return self::$TrustInvalidated;
    }

}



?>
