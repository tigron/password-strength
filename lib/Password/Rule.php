<?php
/**
 * Password_Rule
 *
 * Abstract class to implement a password matching rule
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password;

class Rule {

	/**
	 * Password Strength
	 *
	 * @access private
	 * @var int $strength
	 */
	private ?int $strength = null;

	/**
	 * Conditions
	 *
	 * @access private
	 * @var array $conditions
	 */
	private array $conditions = [];

	/**
	 * Constructor
	 *
	 * @param int $password_strength
	 * @return void
	 */
	public function __construct() {
	}

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function matches($password): bool {
		foreach ($this->conditions as $condition) {
			if (!$condition->matches($password)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Add condition
	 *
	 * @access public
	 * @param \Password\Condition $condition
	 * @return void
	 */
	public function add_condition(\Password\Condition $condition): void {
		$this->conditions[] = $condition;
	}

	/**
	 * Set strength
	 *
	 * @access public
	 * @param int $strength
	 */
	public function set_strength(int $strength): void {
		$this->strength = $strength;
	}

	/**
	 * Get strength
	 *
	 * @access public
	 * @return int $strength
	 */
	public function get_strength(): int {
		return $this->strength;
	}

}
