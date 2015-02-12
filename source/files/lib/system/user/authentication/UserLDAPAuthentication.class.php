<?php
namespace wcf\system\user\authentication;
use wcf\util\LDAPUtil;
use wcf\data\user\User;
use wcf\util\HeaderUtil;

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

		// connect
		if ($ldap->connect(AUTH_TYPE_LDAP_SERVER, AUTH_TYPE_LDAP_SERVER_PORT, AUTH_TYPE_LDAP_SERVER_DN)) {
			$uidField = strtolower(AUTH_TYPE_LDAP_FIELDS_LOGINNAME);
			$wcfUsernameField = strtolower(AUTH_TYPE_LDAP_FIELDS_USERNAME);
			$mailField = strtolower(AUTH_TYPE_LDAP_FIELDS_MAIL);

			// check if plugin is correctly configured, skip this step if not
			if (!empty($uidField) && !empty($mailField)) {
				$bindDN = $uidField . "=" . $loginName . "," . AUTH_TYPE_LDAP_SERVER_DN;
				// find user
				if ($ldap->bind($bindDN, $password)) {
					// try to find user email
					if (($search = $ldap->search($uidField . '=' . $loginName))) {
						$results = $ldap->get_entries($search);
						// set different username
						if (!empty($wcfUsernameField) && isset($results[0][$wcfUsernameField][0])) {
							$this->username = $results[0][$wcfUsernameField][0];
						}

						// set mail address
						if (isset($results[0][$mailField][0])) {
							$this->email = $results[0][$mailField][0];
						}
					}

					$ldap->close();
					return true;
				} else {
					// bind as admin if configured, otherwise anonymous bind
					if (!AUTH_TYPE_LDAP_FIELDS_ANONYMOUSBIND) {
						$bind = $ldap->bind(AUTH_TYPE_LDAP_FIELDS_BINDDN, AUTH_TYPE_LDAP_FIELDS_BINDPW);
					} else {
						$bind = $ldap->bind();
					}

					// search user by e-mail address
					if ($bind && ($this->isValidEmail($loginName) && ($search = $ldap->search($mailField . '=' . $loginName)))) {
						$results = $ldap->get_entries($search);
						if (isset($results[0][$wcfUsernameField][0])) {
							$this->username = $results[0][$wcfUsernameField][0];
							$ldap->close();
							return $this->login($this->username, $password);
						}
					}
				}
			}

			$ldap->close();
		}

		// no ldap user or connection -> check user from wcf
		if(AUTH_CHECK_WCF)
			return $this->checkWCFUser($loginName, $password);

		return false;
	}

	/**
	 * @see	\wcf\system\user\authentication\IUserAuthentication::supportsPersistentLogins()
	 */
	public function supportsPersistentLogins() {
		return true;
	}

	/**
	 * @see	\wcf\system\user\authentication\IUserAuthentication::storeAccessData()
	 */
	public function storeAccessData(User $user, $username, $password) {
		HeaderUtil::setCookie('userID', $user->userID, TIME_NOW + 365 * 24 * 3600);
		HeaderUtil::setCookie('password', $password, TIME_NOW + 365 * 24 * 3600);
	}

	/**
	 * @see	\wcf\system\user\authentication\DefaultUserAuthentication::checkCookiePassword()
	 */
	protected function checkCookiePassword($user, $password) {
		return $this->login($user->username, $password);
	}
}
?>
