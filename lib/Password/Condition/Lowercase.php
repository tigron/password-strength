<?php
/**
 * Condition lowercase
 *
 * This rule checks if a password contains a lower case letter
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Condition;

class Lowercase implements \Password\Condition {

	/**
	 * @var bool $has_lowercase
	 * @access private
	 */
	private bool $has_lowercase = false;

	/**
	 * Constructor
	 *
	 * @access public
	 * @param bool $has_lowercase
	 */
	public function __construct($has_lowercase) {
		$this->has_lowercase = $has_lowercase;
	}

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function matches($password): bool {
		$lowercase = 'abcdefghijklmnopqrstuvwxyz';
		$has_lowercase = false;

		foreach (str_split($lowercase) as $character) {
			if (strpos($password, $character) !== false) {
				$has_lowercase = true;
			}
		}

		if ($has_lowercase === $this->has_lowercase) {
			return true;
		}

		return false;
	}

}

