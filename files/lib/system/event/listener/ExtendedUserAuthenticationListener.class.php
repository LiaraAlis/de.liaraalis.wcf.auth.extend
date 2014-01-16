<?php
namespace wcf\system\event\listener;
use wcf\system\event\IEventListener;
use wcf\system\WCF;

/**
 * @author      Jan Altensen (Stricted) / Alexander Pankow (LiaraAlis)
 * @copyright   2013-2014 Jan Altensen (Stricted) / 2014 Alexander Pankow (LiaraAlis)
 * @license     GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @package     de.liaraalis.wcf.auth.extended
 * @category    Community Framework
 */
class ExtendedUserAuthenticationListener implements IEventListener {
	/**
	 * @see EventListener::execute()
	 */
	public function execute($eventObj, $className, $eventName) {
		if (AUTH_TYPE != 'Default') {
			$eventObj->className = 'wcf\system\user\authentication\User'.AUTH_TYPE.'Authentication';
		}
	}
}
?>
