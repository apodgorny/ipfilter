<?php

	class Parser {
		const COUNTER_FILE = 'counter.txt';

		const PARSE_BLOCK_IP           = '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})';
		const PARSE_BLOCK_BRACKET_DATA = '\[([^\]]+)\]';
		const PARSE_BLOCK_STRING       = '"([^"]*)"';
		const PARSE_BLOCK_NUMERIC      = '([0-9\-]+)';
		const PARSE_BLOCK_IGNORE       = '([ ]*)';

		private $_sBlackIpsFileName = '';

		private $_oLogFile      = null;
		private $_aParseSchema  = [];
		private $_aFilterSchema = [];

		private $_aIps      = [];
		private $_aBlackIps = [];
		private $_aWhiteIps = [];

		private function _error($s) {
			die('Error: ' . $s . PHP_EOL);
		}

		private function _getPosition() {
			if (file_exists(self::COUNTER_FILE)) {
				return intval(file_get_contents(self::COUNTER_FILE));
			}
		}

		private function _savePosition() {
			$nPos = 0;
			if ($this->_oLogFile) {
				$nPos = ftell($this->_oLogFile);
			}
			file_put_contents(self::COUNTER_FILE, $nPos);
		}

		private function _ipMakeExist($aLine) {
			if (!isset($this->_aIps[$aLine['ip']])) {
				$this->_aIps[$aLine['ip']] = [
					'danger' => 0
				];
			}
		}

		private function _increaseDanger($aLine) {
			if (!$this->_isBlackIp($aLine)) {
				$this->_aIps[$aLine['ip']]['danger'] ++;

				if ($this->_aIps[$aLine['ip']]['danger'] >= $this->_aFilterSchema['block_threshold']) {
					$this->_aBlackIps[$aLine['ip']] = 1;
				}
			}
		}

		private function _isBlackIp($aLine) {
			return isset($this->_aBlackIps[$aLine['ip']]);
		}

		private function _isWhiteIp($aLine) {
			return isset($this->_aWhiteIps[$aLine['ip']]);
		}

		private function _ipFilterPath($aLine) {
			if (isset($aLine['request_path'])) {
				foreach ($this->_aFilterSchema['path_regex'] as $sRegex) {
					if (preg_match("/$sRegex/", $aLine['request_path'])) {
						$this->_increaseDanger($aLine);
						return;
					}
				}
			}
		}

		private function _filterLine($aLine) {
			$this->_ipMakeExist($aLine);
			$this->_ipFilterPath($aLine);
		}

		private function _readLine() {
			$sLine = fgets($this->_oLogFile);
			if ($sLine !== false) {
				$aLine = $this->_parseLine($sLine);
				if ($aLine) {
					$this->_filterLine($aLine);
				}
				return true;
			}
			return false;
		}

		private function _doAdditionalParse($f, &$aLine, $sLineKey) {
			if ($f) {
				$a = $f($aLine[$sLineKey]);
				foreach ($a as $sKey=>$sValue) {
					$aLine[$sLineKey. '_' . $sKey] = $sValue;
				}
			}
		}

		private function _parseLine($s) {
			$nPos     = $this->_parseIgnore($s);
			$aLine    = [];
			$aMatches = [];

			foreach ($this->_aParseSchema as $sKey=>$m) {
				$f      = null;
				$sRegex = $m;

				if (is_array($m)) {
					$sRegex = $m[0];
					$f      = isset($m[1]) ? $m[1] : null;
				}

				if (preg_match("/$sRegex/", $s, $aMatches, 0, $nPos)) {
					$aLine[$sKey] = $aMatches[1];
					if ($this->_isBlackIp($aLine)) { return null; }
					if ($this->_isWhiteIp($aLine)) { return null; }
					$nPos += strlen($aMatches[0]);
					$this->_doAdditionalParse($f, $aLine, $sKey);
					$nPos += $this->_parseIgnore($s, $nPos);
				} else {
					$this->_error('Parse failed at "' . $s . '"');
				}
			}
			return $aLine;
		}

		private function _parseIgnore($s, $nPos=0) {
			$nLength  = 0;
			$aMatches = [];

			if (preg_match('/' . self::PARSE_BLOCK_IGNORE . '/', $s, $aMatches, 0, $nPos)) {
				$nLength = strlen($aMatches[0]);
			} else {
				$this->_error('Parse PARSE_BLOCK_IGNORE failed at "' . $s . '"');
			}
			return $nLength;
		}

		/************************ PUBLIC ************************/

		public function __construct($sBlackIpsFileName) {
			$this->_sBlackIpsFileName = $sBlackIpsFileName;
			if (file_exists($sBlackIpsFileName)) {
				$_aBlackIps = json_decode(file_get_contents($sBlackIpsFileName), 1);
			}
		}

		public function parse($sLogFile, $aParseSchema, $aFilterSchema, $aWhiteIps) {
			$this->_aParseSchema  = $aParseSchema;
			$this->_aFilterSchema = $aFilterSchema;
			$this->_aWhiteIps     = array_flip($aWhiteIps);

			if (file_exists($sLogFile)) {
				$this->_oLogFile = fopen($sLogFile, 'r');
				if ($this->_oLogFile) {
					$nPos = $this->_getPosition();
					fseek($this->_oLogFile, $nPos);
					while ($this->_readLine()) {};
					$this->_savePosition();
					fclose($this->_oLogFile);
				} else {
					$this->_error('Could not open ' . $sLogFile);
				}
			} else {
				$this->_error('File ' . $sLogFile . ' does not exist');
			}
			print_r($this->_aBlackIps);
			file_put_contents($this->_sBlackIpsFileName, json_encode($this->_aBlackIps));	
		}
	}

?>