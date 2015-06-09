<?php

	require_once 'class.Parser.php';

	// file_put_contents('counter.txt', 0);

	if (isset($argv[1])) {
		$sLogFile = $argv[1];
	} else {
		die('Pass path to log file as a first parameter' . PHP_EOL);
	}	

	if (isset($argv[2])) {
		$sBlackIpsFileName = $argv[2];
	} else {
		die('Pass filename for black ips as a second parameter' . PHP_EOL);
	}

	$aWhiteIps = [
		'127.0.0.1',
		'12.185.158.130',
		'107.77.75.126'
	];

	$aParseSchema = [
		'ip'            => Parser::PARSE_BLOCK_IP,
		'unknown1'      => Parser::PARSE_BLOCK_NONSPACE,
		'unknown2'      => Parser::PARSE_BLOCK_NONSPACE,
		'date'          => [Parser::PARSE_BLOCK_BRACKET_DATA, function($s) {
			return [
				'timestamp' => @strtotime($s)
			];
		}],
		'request'       => [Parser::PARSE_BLOCK_STRING, function($s) {
			$a = explode(' ', $s);
			return [
				'method'   => isset($a[0]) ? $a[0] : '',
				'path'     => isset($a[1]) ? $a[1] : '',
				'protocol' => isset($a[2]) ? $a[2] : ''
			];
		}],
		'response_code' => Parser::PARSE_BLOCK_NUMERIC,
		'response_size' => Parser::PARSE_BLOCK_NUMERIC,
		'unknown3'      => Parser::PARSE_BLOCK_NONSPACE,
		'browser'       => Parser::PARSE_BLOCK_STRING
	];

	$aFilterSchema = [
		'path_regex' => [
			'^\/\/',
			'^\/\.\.',
			'^\/\.',
			'\.cgi',
			'\.exe',
			'^\/tmUnblock.cgi',
			'^\/muieblackcat',
			'^\/w00tw00t',
			'^\/PMA',
			'^\/pma',
			'^\/admin',
			'^\/dbadmin',
			'^\/sql',
			'^\/mysql',
			'^\/myadmin',
			'^\/phpmyadmin2',
			'^\/phpMyAdmin2',
			'^\/phpMyAdmin-2',
			'^\/php-my-admin',
			'^\/sqlmanager',
			'^\/mysqlmanager',
			'^\/p\/m\/a',
			'^\/php-myadmin',
			'^\/phpmy-admin',
			'^\/webadmin',
			'^\/sqlweb',
			'^\/websql',
			'^\/webdb',
			'^\/mysqladmin',
			'^\/mysql-admin',
			'^\/phpMyAdmin',
			'^\/cgi-bin',
			'^\/cgi-bin\/hi',
			'^\/web-console',
			'^\/\?',
			'^\\x',
			'^\/HNAP1',
			'^\/wp-login',
			'^http',
			'^\/manager'
		],

		'block_threshold'  => 3
	];

	$oParser = new Parser($sLogFile, $sBlackIpsFileName);
	$oParser->parse($aParseSchema, $aFilterSchema, $aWhiteIps);

?>