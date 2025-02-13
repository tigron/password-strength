# Password Strength

This library can calculate the strength of the password based on a given
password ruleset.

## Installation

    composer require tigron/password-strength

## Define a ruleset

In order to calculate a password strength, you must first define a ruleset.
A ruleset is a list of rules which you would like to implement for your
application.

    $ruleset = new \Password\Ruleset();

	// Matches any password. Sets a base score of 'INSECURE'.
    $rule = new \Password\Rule();
    $rule->add_condition(new Condition\Length\Min(0));
    $rule->set_strength(\Password\Strength::VULNERABLE);
    $ruleset->add_rule($rule);

    // More complex passwords can receive a higher score
    $rule = new \Password\Rule();
    $rule->add_condition(new Condition\Length\Min(5));
    $rule->set_strength(\Password\Strength::INSECURE);
    $ruleset->add_rule($rule);

    $rule = new \Password\Rule();
    $rule->add_condition(new Condition\Length\Min(5));
    $rule->add_condition(new Condition\Lowercase(true));
    $rule->add_condition(new Condition\Uppercase(true));
    $rule->set_strength(\Password\Strength::ACCEPTABLE);
    $ruleset->add_rule($rule);


## Test a password

In order to test the password against the defined ruleset, use the following
code

    $ruleset->set_password($password);
    $strength = $ruleset->get_strength();

## Strengths

This library implements 5 levels of strength, all expressed as a score from
0 to 5.

    \Password\Strength::NONE		// Score 0
    \Password\Strength::VULNERABLE		// Score 1
    \Password\Strength::INSECURE		// Score 2
    \Password\Strength::ACCEPTABLE		// Score 3
    \Password\Strength::GOOD		// Score 4
    \Password\Strength::STRONG		// Score 5

If the password did not match any rule, it will receive score 0. This indicates
that a wider base rule needs to be implemented.

## Conditions

The following conditions are implemented and can be used in any rule.

	/**
	 * Put a condition on the presence of an uppercase letter in the password
	 */
    new Condition\Uppercase(bool $requested_value)

	/**
	 * Put a condition on the presence of an lowercase letter in the password
	 */
    new Condition\Lowercase(bool $requested_value)

	/**
	 * Put a condition on the presence of a number
	 */
    new Condition\Number(bool $requested_value)

	/**
	 * Put a condition on the presence of a symbol
	 */
    new Condition\Symbol(bool $requested_value)

	/**
	 * Put a condition on minimum length of the password
	 */
    new Condition\Length\Min(int $length)

	/**
	 * Put a condition on maximum length of the password
	 */
    new Condition\Length\Max(int $length)

	/**
	 * Put a condition on the amount of occurences in haveibeenpwned.com
	 */
    new Condition\Pwned(?int $occurences)

	/**
	 * Put a condition on the score of Zxcvbn
	 * https://lowe.github.io/tryzxcvbn/
	 */
    new Condition\Zxcvbn(int $score)


## Preset

This library has built-in presets of rules that you can include in your project

    /**
     * Hive 2024 password table
     * https://www.hivesystems.com/blog/are-your-passwords-in-the-green
     */
    $ruleset->import_rules(\Password\Preset\Hive2024::export());

    /**
     * Zxcvbn password strength estimator using pattern matching and
     * minimum entropy calculation
     * https://github.com/bjeavons/zxcvbn-php/tree/master
     */
    $ruleset->import_rules(\Password\Preset\Zxcvbn::export());

    /**
     * entropy password strength calculator
     * https://gitlab.com/garybell/password-validation
     */
    $ruleset->import_rules(\Password\Preset\Entropy::export());

    /**
     * Tigron company policy rule. It includes:
     * - Hive 2024
     * - Zxcvbn
     * - entropy
     */
    $ruleset->import_rules(\Password\Preset\Tigron::export());
