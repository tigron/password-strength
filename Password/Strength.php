<?php
/**
 * Password_Strength
 *
 * This class defines some constants to indicate the strength of a given
 * password
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */
class Password_Strength {

	const NONE = 0; // No strength, rule did not match
	const VULNERABLE = 1;
	const INSECURE = 2;
	const ACCEPTABLE = 3;
	const GOOD = 4;
	const STRONG = 5;

}
