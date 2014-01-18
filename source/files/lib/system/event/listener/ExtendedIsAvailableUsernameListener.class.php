<?php
namespace wcf\system\event\listener;
use wcf\system\event\IEventListener;
use wcf\util\LDAPUtil;
use wcf\system\exception\UserInputException;

/**
 * Extend register validation and check if username is already taken in different services (e.g. LDAP)
 *
 * @author      Alexander Pankow (LiaraAlis)
 * @copyright   2014 Alexander Pankow (LiaraAlis)
 * @license     GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @package     de.liaraalis.wcf.auth.extended
 * @category    Community Framework
 */
class ExtendedIsAvailableUsernameListener implements IEventListener {
	/**
	 * @param \wcf\form\RegisterForm $eventObj
	 * @param string $className
	 * @param string $eventName
	 * @see EventListener::execute()
	 */
	public function execute($eventObj, $className, $eventName) {
		try {
			switch(AUTH_TYPE) {
				case 'LDAP':
					$this->isAvailableUsernameInLDAP($eventObj->username);
					break;
			}
		}
		catch (UserInputException $e) {
			$eventObj->errorType[$e->getField()] = $e->getType();
		}
	}

	/**
	 * check, if username is already taken in ldap
	 *
	 * @param string $username
	 * @throws \wcf\system\exception\UserInputException
	 */
	protected function isAvailableUsernameInLDAP($username) {
		$ldap = new LDAPUtil();

		if ($ldap->connect(AUTH_TYPE_LDAP_SERVER, AUTH_TYPE_LDAP_SERVER_PORT, AUTH_TYPE_LDAP_SERVER_DN)) {
			if (!AUTH_TYPE_LDAP_FIELDS_ANONYMOUSBIND) {
				$bind = $ldap->bind(AUTH_TYPE_LDAP_FIELDS_BINDDN, AUTH_TYPE_LDAP_FIELDS_BINDPW);
			} else {
				$bind = $ldap->bind();
			}

			if ($bind && ($search = $ldap->search(AUTH_TYPE_LDAP_FIELDS_LOGINNAME . '=' . $username))) {
				$results = $ldap->get_entries($search);
				if ($results['count'] > 0)
					throw new UserInputException('username', 'notValid');
			}
		}
	}
}
