<?php
/**
 * Password_Rule_Regex
 *
 * This rule will check if the password matches a given regular expression
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

class Password_Rule_Regex extends Password_Rule {

	/**
	 * Regexp
	 *
	 * @access public
	 * @var string $regex
	 */
	public $regex = '';

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function rule_matches(): bool {
		preg_match('/' . $this->regex . '/', $this->password, $output);
		if (count($output) > 0) {
			return true;
		}
		return false;
	}

}

