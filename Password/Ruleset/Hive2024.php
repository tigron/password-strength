<?php
/**
 * Password_Ruleset_Hive2024
 *
 * This ruleset will validate a password against the Hive 2024 rules:
 * https://www.hivesystems.com/blog/are-your-passwords-in-the-green
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Ruleset;

class Hive2024 extends \Password\Ruleset {

	/**
	 * Create
	 *
	 * @access public
	 * @return Password_Ruleset_Hive2024 $password_ruleset
	 */
	public static function create(): Password_Ruleset_Hive2024 {
		$ruleset = new self();

		// Numbers only
		$rule = new Password_Rule_Regex(Password_Strength::VULNERABLE);
		$rule->regexp = '^[\d\h]{1,6}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::INSECURE);
		$rule->regexp = '^[\d\h]{7,14}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::ACCEPTABLE);
		$rule->regexp = '^[\d\h]{15,}\z$';
		$ruleset->add_password_rule($rule);

		// Lowercase letters
		$rule = new Password_Rule_Regex(Password_Strength::VULNERABLE);
		$rule->regexp = '^[a-z\h]{1,4}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::INSECURE);
		$rule->regexp = '^[a-z\h]{5,9}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::ACCEPTABLE);
		$rule->regexp = '^[a-z\h]{10,13}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::GOOD);
		$rule->regexp = '^[a-z\h]{14,16}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::STRONG);
		$rule->regexp = '^[a-z\h]{17,}\z$';
		$ruleset->add_password_rule($rule);

		// Upper and Lowercase letters
		$rule = new Password_Rule_Regex(Password_Strength::INSECURE);
		$rule->regexp = '^(?=.*[a-z\h])(?=.*[A-Z]).{1,8}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::ACCEPTABLE);
		$rule->regexp = '^(?=.*[a-z\h])(?=.*[A-Z]).{9,11}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::GOOD);
		$rule->regexp = '^(?=.*[a-z\h])(?=.*[A-Z]).{12,13}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::STRONG);
		$rule->regexp = '^(?=.*[a-z\h])(?=.*[A-Z]).{14,}\z$';
		$ruleset->add_password_rule($rule);

		// Numbers, Upper and Lowercase letters
		$rule = new Password_Rule_Regex(Password_Strength::INSECURE);
		$rule->regexp = '^(?=.*\d)(?=.*[a-z\h])(?=.*[A-Z]).{1,7}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::ACCEPTABLE);
		$rule->regexp = '^(?=.*\d)(?=.*[a-z\h])(?=.*[A-Z]).{8,10}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::GOOD);
		$rule->regexp = '^(?=.*\d)(?=.*[a-z\h])(?=.*[A-Z]).{11,13}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::STRONG);
		$rule->regexp = '^(?=.*\d)(?=.*[a-z\h])(?=.*[A-Z]).{14,}\z$';
		$ruleset->add_password_rule($rule);

		// Numbers, Upper and Lowercase letters, Symbols
		$rule = new Password_Rule_Regex(Password_Strength::INSECURE);
		$rule->regexp = '^(?=.*\d)(?=.*[a-z\h])(?=.*[A-Z])(?=.*?[\W_]).{1,7}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::ACCEPTABLE);
		$rule->regexp = '^(?=.*\d)(?=.*[a-z\h])(?=.*[A-Z])(?=.*?[\W_]).{8,10}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::GOOD);
		$rule->regexp = '^(?=.*\d)(?=.*[a-z\h])(?=.*[A-Z])(?=.*?[\W_]).{11,13}\z$';
		$ruleset->add_password_rule($rule);

		$rule = new Password_Rule_Regex(Password_Strength::STRONG);
		$rule->regexp = '^(?=.*\d)(?=.*[a-z\h])(?=.*[A-Z])(?=.*?[\W_]).{14,}\z$';
		$ruleset->add_password_rule($rule);

		return $ruleset;
	}

}
