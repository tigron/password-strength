<?php
/**
 * Password_Ruleset
 *
 * The ruleset combines a set of rules. When calculating the password strength
 * for a given ruleset, we search for the rule with the HIGHEST score inside
 * the ruleset.
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */
class Password_Ruleset {

	/**
	 * Rules
	 *
	 * @access private
	 * @var Password_Rule[] $password_rules
	 */
	private $password_rules = [];

	/**
	 * The password to verify
	 *
	 * @access private
	 * @var string $password
	 */
	private ?string $password = null;

	/**
	 * Add password_rule
	 *
	 * @access public
	 * @param Password_Rule $password_rule
	 */
	public function add_password_rule(Password_Rule $password_rule): void {
		$this->password_rules[] = $password_rule;
	}

	/**
	 * Set password
	 *
	 * @access public
	 * @param string $password
	 * @return void
	 */
	public function set_password(string $password): void {
		$this->password = $password;	
	}

	/**
	 * Get strength
	 *
	 * @access public
	 * @return int $strength
	 */
	public function get_strength(): int {
		$highest_strength = Password_Strength::NONE;
		foreach ($this->password_rules as $password_rule) {
			$password_rule->set_password($this->password);
			$rule_strength = $password_rule->get_strength();
			if ($rule_strength > $highest_strength) {
				$highest_strength = $rule_strength;
			}
		}
		return $highest_strength;
	}	
}
