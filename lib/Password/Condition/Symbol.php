<?php
/**
 * Condition symbol
 *
 * This rule checks if a password contains a symbol
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Condition;

class Symbol implements \Password\Condition {

	/**
	 * @var bool $has_symbol
	 * @access private
	 */
	private bool $has_symbol = false;

	/**
	 * Constructor
	 *
	 * @access public
	 * @param bool $has_symbol
	 */
	public function __construct($has_symbol) {
		$this->has_symbol = $has_symbol;
	}

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function matches($password): bool {
		$characters  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$characters .= 'abcdefghijklmnopqrstuvwxyz';
		$characters .= '1234567890';
		$characters = str_split($characters);

		$has_symbol = false;

		foreach (str_split($password) as $password_character) {
			if (!in_array($password_character, $characters)) {
				$has_symbol = true;
			}
		}

		if ($has_symbol === $this->has_symbol) {
			return true;
		}

		return false;
	}

}

