<?php

	class Parser {
		const PARSE_BLOCK_IP           = '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})';
		const PARSE_BLOCK_BRACKET_DATA = '\[([^\]]+)\]';
		const PARSE_BLOCK_STRING       = '"([^"]*)"';
		const PARSE_BLOCK_NUMERIC      = '([0-9\-]+)';
		const PARSE_BLOCK_NONSPACE     = '([^ ]*)';
		const PARSE_BLOCK_IGNORE       = '([ ]*)';

		private $_sBlackIpsFileName = '';
		private $_sLogFile          = '';
		private $_sCounterFile      = '';

		private $_oLogFile      = null;
		private $_aParseSchema  = [];
		private $_aFilterSchema = [];

		private $_aIps      = [];
		private $_aBlackIps = [];
		private $_aWhiteIps = [];

		private function _error($s, $bDie=true) {
			print 'Error: ' . $s . PHP_EOL;
			if ($bDie) {
				exit(1);
			}
		}

		private function _saveBlackIps() {
			file_put_contents($this->_sBlackIpsFileName, implode("\n", array_keys($this->_aBlackIps)));
		}

		private function _openBlackIps() {
			if (file_exists($this->_sBlackIpsFileName)) {
				$sFileContents = trim(file_get_contents($this->_sBlackIpsFileName));
				$this->_aBlackIps = array_flip(explode("\n", $sFileContents));
			}
		}

		private function _getCounterFileName() {
			if ($this->_sCounterFile === '') {
				$this->_sCounterFile = dirname(__FILE__) . '/' . md5($this->_sLogFile) . '.counter';
				//print $this->_sCounterFile . PHP_EOL;
			}
			return $this->_sCounterFile;
		}		 

		private function _getPosition() {
			if (file_exists($this->_getCounterFileName())) {
				return intval(file_get_contents($this->_getCounterFileName()));
			} else {
				return 0;
			}
		}

		private function _savePosition() {
			$nPos = 0;
			if ($this->_oLogFile) {
				$nPos = ftell($this->_oLogFile);
			}
			file_put_contents($this->_getCounterFileName(), $nPos);
			//print 'Saving position at ' . $nPos . PHP_EOL;
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
					print 'Blacklist: ' . $aLine['ip'] . PHP_EOL;
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

		private function _goToNextNewLine() {
			if (ftell($this->_oLogFile) > 0) {
				fseek($this->_oLogFile, -2);
			}
			do {
				$sChar = fread($this->_oLogFile, 1);
			} while ($sChar !== "\n" && ftell($this->_oLogFile) < filesize($this->_sLogFile));

			if (ftell($this->_oLogFile) >= filesize($this->_sLogFile)) {
				$this->_savePosition();
			}
		}

		private function _goToReadPosition() {
			$nPos = $this->_getPosition();
			if ($nPos > 0) {
				$nPos --;
			}
			fseek($this->_oLogFile, $nPos);
			$this->_goToNextNewLine();
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
					$this->_error('Parse failed at "' . $s . '" while parsing "' . $sKey . '" at byte ' . ftell($this->_oLogFile), false);
					$this->_goToNextNewLine();
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
				$this->_error('Parse PARSE_BLOCK_IGNORE failed at "' . $s . '"', false);
				$this->_goToNextNewLine();
			}
			return $nLength;
		}

		/************************ PUBLIC ************************/

		public function __construct($sLogFile, $sBlackIpsFileName) {
			$this->_sLogFile          = $sLogFile;
			$this->_sBlackIpsFileName = $sBlackIpsFileName;

			$this->_openBlackIps();
		}

		public function parse($aParseSchema, $aFilterSchema, $aWhiteIps) {
			$this->_aParseSchema  = $aParseSchema;
			$this->_aFilterSchema = $aFilterSchema;
			$this->_aWhiteIps     = array_flip($aWhiteIps);

			if (file_exists($this->_sLogFile)) {
				$this->_oLogFile = fopen($this->_sLogFile, 'r');
				if ($this->_oLogFile) {
					$this->_goToReadPosition();
					while ($this->_readLine()) {};
					$this->_savePosition();
					fclose($this->_oLogFile);
				} else {
					$this->_error('Could not open ' . $this->_sLogFile);
				}
			} else {
				$this->_error('File ' . $this->_sLogFile . ' does not exist');
			}
			$this->_saveBlackIps();	
		}
	}

?>