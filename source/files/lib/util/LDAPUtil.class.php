<?php
namespace wcf\util;
use wcf\system\WCF;
use wcf\system\exception\SystemException;

/**
 * @author      Jan Altensen (Stricted) / Alexander Pankow (LiaraAlis)
 * @copyright   2013-2014 Jan Altensen (Stricted) / 2014 Alexander Pankow (LiaraAlis)
 * @license     GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @package     de.liaraalis.wcf.auth.extended
 * @category    Community Framework
 */
class LDAPUtil {
	/**
	 * LDAP resource id
	 */
	protected $ldap = null;
	
	/**
	 * LDAP DN
	 */
	protected $dn = '';
	
	/**
	 * Constructs a new instance of LDAPUtil.
	 */
	public function __construct () {
		if(!extension_loaded("ldap")) {
			throw new SystemException("Can not find LDAP extension.");
		}
	}
	
	/**
	 * connect to a ldap server
	 *
	 * @param	string	$server
	 * @param	integer	$port
	 * @param	string	$dn
	 * @return	bool	true/false
	 */
	public function connect ($server, $port, $dn) {
		if (empty($server) || empty($port) || empty($dn))
			return false;

		if(strpos($server, '://') !== false) {
			// ldap_connect ignores port parameter when URLs are passed
			$server .= ':' . $port;
		}

		$this->ldap = @ldap_connect($server, $port);
		$this->dn = $dn;
		if($this->ldap) {
			ldap_set_option($this->ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
			ldap_set_option($this->ldap, LDAP_OPT_REFERRALS, 0);
			return true;
		}

		return false;
	}
	
	/**
	 *	returns ldap user array
	 *
	 *	@param	string	$bindDN
	 *	@param	string	$bindPW
	 *	@return	array
	 */
	public function bind ($bindDN = null, $bindPW = null) {
		if ($bindDN === null || $bindPW === null) {
			// anonymous bind
			$bind = @ldap_bind($this->ldap);
		} else {
			$bind = @ldap_bind($this->ldap, $bindDN, $bindPW);
		}

		return $bind;
	}
	
	/**
	 *	search user on ldap server
	 *
	 * @param	string	$search
	 * @return	resource
	 */
	public function search ($search) {
		return ldap_search($this->ldap, $this->dn, $search);
	}
	
	/**
	 * get entries from search resource
	 *
	 * @param	resource	$resource
	 * @return	array
	 */
	public function get_entries ($resource) {
		return ldap_get_entries($this->ldap, $resource);
	}
	
	/**
	 * close ldap connection
	 */
	public function close () {
		ldap_close($this->ldap);
	}
}
?>
