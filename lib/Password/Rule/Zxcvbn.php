<?php
/**
 * Password_Rule_Regex
 *
 * This rule will check if the password matches a given regular expression
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Rule;

use ZxcvbnPhp\Zxcvbn;

class Zxcvbn extends \Password\Rule {

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function rule_matches(): bool {
		return true;
	}

	/**
	 * Get strength
	 *
	 * @access public
	 * @return int $strength
	 */
	public function get_strength(): int {

	}	

}

