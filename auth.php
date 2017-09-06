<?php
/**
 * DokuWiki Plugin authimap2 (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Marco Fenoglio <marco.fenoglio@to.infn.it>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class auth_plugin_authimap2 extends DokuWiki_Auth_Plugin {
    /** @var array user cache */
    protected $users = null;

    /** @var array filter pattern */
    protected $_pattern = array();

    /** @var bool safe version of preg_split */
    protected $_pregsplit_safe = false;

    /**
     * Constructor.
     */
    public function __construct() {
        parent::__construct(); // for compatibility

        if(!function_exists('imap_open')) {
            msg('PHP IMAP extension not available, IMAP auth not available.', -1);
            return;
        }
        if(!$this->getConf('server')) {
            msg('IMAP auth is missing server configuration', -1);
            return;
        }
        if(!$this->getConf('domain')) {
            msg('IMAP auth is missing domain configuration', -1);
            return;
        }

        global $config_cascade;

        if(!@is_readable($config_cascade['plainauth.users']['default'])) {
            $this->success = false;
        } else {
            if(@is_writable($config_cascade['plainauth.users']['default'])) {
                $this->cando['addUser']   = true;
                $this->cando['delUser']   = true;
                $this->cando['modLogin']  = true;
                $this->cando['modPass']   = false;
                $this->cando['modName']   = true;
                $this->cando['modMail']   = true;
                $this->cando['modGroups'] = true;
            }
            $this->cando['getUsers']     = true;
            $this->cando['getUserCount'] = true;
        }

        $this->_pregsplit_safe = version_compare(PCRE_VERSION,'6.7','>=');
    }

    /**
     * Check user+password
     *
     * May be ommited if trustExternal is used.
     *
     * @param   string $user the user name
     * @param   string $pass the clear text password
     * @return  bool
     */
    public function checkPass($user, $pass) {
        $userinfo = $this->getUserData($user);
        if ($userinfo === false) return false;

        $domain = $this->getConf('domain');
        $server = $this->getConf('server');

        $toReturn=false; 

        // some servers want the local part, others want the full address as username
        if($this->getConf('usedomain')) {
            $login = "$user@$domain";
        } else {
            $login = $user;
        }
        // check at imap server
        #$imap_login = @imap_open("{imap.to.infn.it:993/imap/ssl/novalidate-cert}",
        $imap_login = @imap_open($server, $login, $pass, OP_READONLY);

        if ($imap_login == false){
            $toReturn = false;
        }
        else {
            $toReturn = true;
            imap_close($imap_login);
        }	

        return $toReturn;
    }

    /**
     * Return user info
     *
     * Returns info about the given user needs to contain
     * at least these fields:
     *
     * name string  full name of the user
     * mail string  email addres of the user
     * grps array   list of groups the user is in
     *
     * @param   string $user the user name
     * @return  array containing user data or false
     * @param   bool $requireGroups whether or not the returned data must include groups
     */
    public function getUserData($user, $requireGroups=true) {
        if($this->users === null) $this->_loadUserData();
        return isset($this->users[$user]) ? $this->users[$user] : false;
    }

    /**
     * Creates a string suitable for saving as a line
     * in the file database
     * (delimiters escaped, etc.)
     *
     * @param string $user
     * @param string $pass
     * @param string $name
     * @param string $mail
     * @param array  $grps list of groups the user is in
     * @return string
     */
    protected function _createUserLine($user, $pass, $name, $mail, $grps) {
        $groups   = join(',', $grps);
        $userline = array($user, $pass, $name, $mail, $groups);
        $userline = str_replace('\\', '\\\\', $userline); // escape \ as \\
        $userline = str_replace(':', '\\:', $userline); // escape : as \:
        $userline = join(':', $userline)."\n";
        return $userline;
    }

    /**
     * Create a new User [implement only where required/possible]
     *
     * Returns false if the user already exists, null when an error
     * occurred and true if everything went well.
     *
     * The new user HAS TO be added to the default group by this
     * function!
     *
     * Set addUser capability when implemented
     *
     * @param  string     $user
     * @param  string     $pass
     * @param  string     $name
     * @param  string     $mail
     * @param  null|array $grps
     * @return bool|null
     */
    public function createUser($user, $pass, $name, $mail, $grps = null) {
        global $conf;
        global $config_cascade;

        // user mustn't already exist
        if($this->getUserData($user) !== false) {
            msg($this->getLang('userexists'), -1);
            return false;
        }

        $pass = auth_cryptPassword($pwd);

        // set default group if no groups specified
        if(!is_array($grps)) $grps = array($conf['defaultgroup']);

        // prepare user line
        $userline = $this->_createUserLine($user, $pass, $name, $mail, $grps);

        if(!io_saveFile($config_cascade['plainauth.users']['default'], $userline, true)) {
            msg($this->getLang('writefail'), -1);
            return null;
        }

        $this->users[$user] = compact('pass', 'name', 'mail', 'grps');
        return $pwd;
    }

    /**
     * Modify user data [implement only where required/possible]
     *
     * Set the mod* capabilities according to the implemented features
     *
     * @param   string $user    nick of the user to be changed
     * @param   array  $changes array of field/value pairs to be changed (password will be clear text)
     * @return  bool
     */
    public function modifyUser($user, $changes) {
        global $ACT;
        global $config_cascade;

        // sanity checks, user must already exist and there must be something to change
        if(($userinfo = $this->getUserData($user)) === false) {
            msg($this->getLang('usernotexists'), -1);
            return false;
        }

        // don't modify protected users
        if(!empty($userinfo['protected'])) {
            msg(sprintf($this->getLang('protected'), hsc($user)), -1);
            return false;
        }

        if(!is_array($changes) || !count($changes)) return true;

        // update userinfo with new data, remembering to encrypt any password
        $newuser = $user;
        foreach($changes as $field => $value) {
            if($field == 'user') {
                $newuser = $value;
                continue;
            }
            if($field == 'pass') $value = auth_cryptPassword($value);
            $userinfo[$field] = $value;
        }

        $userline = $this->_createUserLine($newuser, $userinfo['pass'], $userinfo['name'], $userinfo['mail'], $userinfo['grps']);

        if(!io_replaceInFile($config_cascade['plainauth.users']['default'], '/^'.$user.':/', $userline, true)) {
            msg('There was an error modifying your user data. You may need to register again.', -1);
            // FIXME, io functions should be fail-safe so existing data isn't lost
            $ACT = 'register';
            return false;
        }

        $this->users[$newuser] = $userinfo;
        return true;
    }

    /**
     * Delete one or more users [implement only where required/possible]
     *
     * Set delUser capability when implemented
     *
     * @param   array  $users
     * @return  int    number of users deleted
     */
    public function deleteUsers($users) {
        global $config_cascade;

        if(!is_array($users) || empty($users)) return 0;

        if($this->users === null) $this->_loadUserData();

        $deleted = array();
        foreach($users as $user) {
            // don't delete protected users
            if(!empty($this->users[$user]['protected'])) {
                msg(sprintf($this->getLang('protected'), hsc($user)), -1);
                continue;
            }
            if(isset($this->users[$user])) $deleted[] = preg_quote($user, '/');
        }

        if(empty($deleted)) return 0;

        $pattern = '/^('.join('|', $deleted).'):/';
        if (!io_deleteFromFile($config_cascade['plainauth.users']['default'], $pattern, true)) {
            msg($this->getLang('writefail'), -1);
            return 0;
        }

        // reload the user list and count the difference
        $count = count($this->users);
        $this->_loadUserData();
        $count -= count($this->users);
        return $count;
    }

    /**
     * Bulk retrieval of user data [implement only where required/possible]
     *
     * Set getUsers capability when implemented
     *
     * @param   int   $start     index of first user to be returned
     * @param   int   $limit     max number of users to be returned, 0 for unlimited
     * @param   array $filter    array of field/pattern pairs, null for no filter
     * @return  array list of userinfo (refer getUserData for internal userinfo details)
     */
    public function retrieveUsers($start = 0, $limit = 0, $filter = null) {

        if($this->users === null) $this->_loadUserData();

        ksort($this->users);

        $i     = 0;
        $count = 0;
        $out   = array();
        $this->_constructPattern($filter);

        foreach($this->users as $user => $info) {
            if($this->_filter($user, $info)) {
                if($i >= $start) {
                    $out[$user] = $info;
                    $count++;
                    if(($limit > 0) && ($count >= $limit)) break;
                }
                $i++;
            }
        }

        return $out;
    }

    /**
     * Return a count of the number of user which meet $filter criteria
     * [should be implemented whenever retrieveUsers is implemented]
     *
     * Set getUserCount capability when implemented
     *
     * @param  array $filter array of field/pattern pairs, empty array for no filter
     * @return int
     */
    public function getUserCount($filter = array()) {

        if($this->users === null) $this->_loadUserData();

        if(!count($filter)) return count($this->users);

        $count = 0;
        $this->_constructPattern($filter);

        foreach($this->users as $user => $info) {
            $count += $this->_filter($user, $info);
        }

        return $count;
    }

    /**
     * Return case sensitivity of the backend
     *
     * When your backend is caseinsensitive (eg. you can login with USER and
     * user) then you need to overwrite this method and return false
     *
     * @return bool
     */
    public function isCaseSensitive() {
        return true;
    }

    /**
     * Sanitize a given username
     *
     * This function is applied to any user name that is given to
     * the backend and should also be applied to any user name within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce username restrictions.
     *
     * @param string $user username
     * @return string the cleaned username
     */
    public function cleanUser($user) {
        global $conf;
        return cleanID(str_replace(':', $conf['sepchar'], $user));
    }

    /**
     * Sanitize a given groupname
     *
     * This function is applied to any groupname that is given to
     * the backend and should also be applied to any groupname within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce groupname restrictions.
     *
     * Groupnames are to be passed without a leading '@' here.
     *
     * @param  string $group groupname
     * @return string the cleaned groupname
     */
    public function cleanGroup($group) {
        global $conf;
        return cleanID(str_replace(':', $conf['sepchar'], $group));
    }

    /**
     * Load all user data
     *
     * loads the user file into a datastructure
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     */
    protected function _loadUserData() {
        global $config_cascade;

        $this->users = $this->_readUserFile($config_cascade['plainauth.users']['default']);

        // support protected users
        if(!empty($config_cascade['plainauth.users']['protected'])) {
            $protected = $this->_readUserFile($config_cascade['plainauth.users']['protected']);
            foreach(array_keys($protected) as $key) {
                $protected[$key]['protected'] = true;
            }
            $this->users = array_merge($this->users, $protected);
        }
    }

    /**
     * Read user data from given file
     *
     * ignores non existing files
     *
     * @param string $file the file to load data from
     * @return array
     */
    protected function _readUserFile($file) {
        $users = array();
        if(!file_exists($file)) return $users;

        $lines = file($file);
        foreach($lines as $line) {
            $line = preg_replace('/#.*$/', '', $line); //ignore comments
            $line = trim($line);
            if(empty($line)) continue;

            $row = $this->_splitUserData($line);
            $row = str_replace('\\:', ':', $row);
            $row = str_replace('\\\\', '\\', $row);

            $groups = array_values(array_filter(explode(",", $row[4])));

            $users[$row[0]]['pass'] = $row[1];
            $users[$row[0]]['name'] = urldecode($row[2]);
            $users[$row[0]]['mail'] = $row[3];
            $users[$row[0]]['grps'] = $groups;
        }
        return $users;
    }

    protected function _splitUserData($line){
        // due to a bug in PCRE 6.6, preg_split will fail with the regex we use here
        // refer github issues 877 & 885
        if ($this->_pregsplit_safe){
            return preg_split('/(?<![^\\\\]\\\\)\:/', $line, 5);       // allow for : escaped as \:
        }

        $row = array();
        $piece = '';
        $len = strlen($line);
        for($i=0; $i<$len; $i++){
            if ($line[$i]=='\\'){
                $piece .= $line[$i];
                $i++;
                if ($i>=$len) break;
            } else if ($line[$i]==':'){
                $row[] = $piece;
                $piece = '';
                continue;
            }
            $piece .= $line[$i];
        }
        $row[] = $piece;

        return $row;
    }

    /**
     * return true if $user + $info match $filter criteria, false otherwise
     *
     * @author   Chris Smith <chris@jalakai.co.uk>
     *
     * @param string $user User login
     * @param array  $info User's userinfo array
     * @return bool
     */
    protected function _filter($user, $info) {
        foreach($this->_pattern as $item => $pattern) {
            if($item == 'user') {
                if(!preg_match($pattern, $user)) return false;
            } else if($item == 'grps') {
                if(!count(preg_grep($pattern, $info['grps']))) return false;
            } else {
                if(!preg_match($pattern, $info[$item])) return false;
            }
        }
        return true;
    }

    /**
     * construct a filter pattern
     *
     * @param array $filter
     */
    protected function _constructPattern($filter) {
        $this->_pattern = array();
        foreach($filter as $item => $pattern) {
            $this->_pattern[$item] = '/'.str_replace('/', '\/', $pattern).'/i'; // allow regex characters
        }
    }

}

// vim:ts=4:sw=4:et:
