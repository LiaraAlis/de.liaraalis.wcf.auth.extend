<?php
namespace wcf\system\user\authentication;
use wcf\data\user\group\UserGroup;
use wcf\data\user\UserAction;
use wcf\data\user\User;
use wcf\data\user\UserEditor;
use wcf\data\user\UserProfileAction;
use wcf\system\exception\SystemException;
use wcf\system\exception\UserInputException;
use wcf\util\HeaderUtil;
use wcf\util\PasswordUtil;
use wcf\system\database\MySQLDatabase;
use wcf\system\database\PostgreSQLDatabase;
use wcf\util\LDAPUtil;
use wcf\util\UserUtil;
use wcf\system\language\LanguageFactory;
use wcf\system\WCF;

/**
 * @author      Jan Altensen (Stricted) / Alexander Pankow (LiaraAlis)
 * @copyright   2013-2014 Jan Altensen (Stricted) / 2014 Alexander Pankow (LiaraAlis)
 * @license     GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @package     de.liaraalis.wcf.auth.extended
 * @category    Community Framework
 */
class UserLDAPAuthentication extends UserAbstractAuthentication {

	/**
	 * Checks the given user data.
	 *
	 * @param	string		$loginName
	 * @param 	string		$password
	 * @return	boolean
	 */
	protected function login ($loginName, $password) {
		$ldap = new LDAPUtil();

		$host = AUTH_TYPE_LDAP_SERVER;
		$port = AUTH_TYPE_LDAP_SERVER_PORT;
		$baseDN = AUTH_TYPE_LDAP_SERVER_DN;

		if(strpos($host, '://') !== false) {
			// ldap_connect ignores port parameter when URLs are passed
			$host .= ':' . $port;
		}

		// connect
		$connect = $ldap->connect($host, $port, $baseDN);
		if ($connect) {
			$uidField = AUTH_TYPE_LDAP_FIELDS_LOGINNAME;
			$wcfUsernameField = AUTH_TYPE_LDAP_FIELDS_USERNAME;
			$mailField = AUTH_TYPE_LDAP_FIELDS_MAIL;

			// find user
			if ($ldap->bind($loginName, $password)) {
				// try to find user email
				if (($search = $ldap->search($uidField . '=' . $loginName))) {
					$results = $ldap->get_entries($search);
					if (isset($results[0][$mailField][0])) {
						$this->email = $results[0][$mailField][0];
					}
				}
				
				$ldap->close();
				return true;
			} else if ($this->isValidEmail($loginName) && ($search = $ldap->search($mailField . '=' . $loginName))) {
				$results = $ldap->get_entries($search);
				if(isset($results[0][$wcfUsernameField][0])) {
					$this->username = $results[0][$wcfUsernameField][0];
					$ldap->close($connect);
					return $this->login($this->username, $password);
				}
			}
		}
		// no ldap user or connection -> check user from wcf
		$ldap->close($connect);

		if(AUTH_CHECK_WCF)
			return $this->checkWCFUser($loginName, $password);

		return false;
	}
}
?>
