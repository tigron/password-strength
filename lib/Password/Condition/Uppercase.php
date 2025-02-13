<?php
/**
 * Condition uppercase
 *
 * This rule checks if a password contains an uppercase letter
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Condition;

class Uppercase implements \Password\Condition {

	/**
	 * @var bool $has_lowercase
	 * @access private
	 */
	private bool $has_uppercase = false;

	/**
	 * Constructor
	 *
	 * @access public
	 * @param bool $has_lowercase
	 */
	public function __construct($has_uppercase) {
		$this->has_uppercase = $has_uppercase;
	}

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function matches($password): bool {
		$uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$has_uppercase = false;

		foreach (str_split($uppercase) as $character) {
			if (strpos($password, $character) !== false) {
				$has_uppercase = true;
			}
		}

		if ($has_uppercase === $this->has_uppercase) {
			return true;
		}

		return false;
	}

}

