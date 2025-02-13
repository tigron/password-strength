<?php
/**
 * Password_Rule_Regex
 *
 * This rule will check if the password matches a given regular expression
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password;

interface Condition {

	/**
	 * Does the given password matches this condition
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function matches($password): bool;

}

