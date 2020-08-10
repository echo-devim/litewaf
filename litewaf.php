<?php

class LiteWAF {
	/*
	 * LiteWAF is a lightweight in-app Web Application Firewall.
	 * This tool is self-contained in a single PHP page. Include this PHP file in every page you want to protect.
	 * LiteWAF intercepts the request and it does some basic sanity checks.
	 */

	/* ------ USER CONFIGURATION VARIABLES (edit here your settings) -------- */
	private $ALLOW_ARRAYS=false; //Allow an array to be passed as parameter. If this property is set to true the array is passed without checks (maybe this will be fixed in the next releases)
	private $REDIRECT_PAGE=""; //Relative path where to redirect the user if an attack is detected (empty string redirects to the index)
	private $LOG_FILEPATH="attacklogs.php";
	private $LITEWAF_PATH=""; //Directory that contains litewaf.php (leave blank if it is in the root directory). Directory path must end with '/'
	private $LOG_PASSWORD=""; //Set the password to access the log file
	private $LOG_REDIRECT=true; //if true, when someone tries to access the log page using incorrect credentials he will be redirected to $REDIRECT_PAGE otherwise "Not Authorized" message is displayed
	/* ------ END USER CONFIGURATION (Do not touch code below) ------ */

	const PRODUCT='LiteWAF';
	const VERSION='1.0';
	private $xss_markers = array("</", "<script", "/>", "onabort=","onauxclick=","oncancel=","oncanplay=","oncanplaythrough=","onchange=","onclick=","onclose=","oncontextmenu=","oncuechange=","ondblclick=","ondrag=","ondragend=","ondragenter=","ondragexit=","ondragleave=","ondragover=","ondragstart=","ondrop=","ondurationchange=","onemptied=","onended=","onformdata=","oninput=","oninvalid=","onkeydown=","onkeypress=","onkeyup=","onloadeddata=","onloadedmetadata=","onloadstart=","onmousedown=","onmouseenter=","onmouseleave=","onmousemove=","onmouseout=","onmouseover=","onmouseup=","onpause=","onplay=","onplaying=","onprogress=","onratechange=","onreset=","onsecuritypolicyviolation=","onseeked=","onseeking=","onselect=","onslotchange=","onstalled=","onsubmit=","onsuspend=","ontimeupdate=","ontoggle=","onvolumechange=","onwaiting=","onwebkitanimationend=","onwebkitanimationiteration=","onwebkitanimationstart=","onwebkittransitionend=","onwheel=","onblur=","onerror=","onfocus=","onload=","onresize=","onscroll=","onafterprint=","onbeforeprint=","onbeforeunload=","onhashchange=","onlanguagechange=","onmessage=","onmessageerror=","onoffline=","ononline=","onpagehide=","onpageshow=","onpopstate=","onrejectionhandled=","onstorage=","onunhandledrejection=","onunload=","oncut=","oncopy=","onpaste=","onreadystatechange=","<iframe", "javascript:","<frame","<embed","<object","href=","src=");
	
	private $sqli_markers = array("select*from", ";--","droptable", "selectif","'select","unionall","'and'","'or'", "unionselect","orderby","insertinto","intooutfile","benchmark(","waitfordelay","waitfortime","sleep(");
	
	private $pathtraversal_markers = array("..\\","../","..\\/");
	
	private $rce_markers = array("bin/", "cmd/", "&&", ">/", "system(","exec("); //Note: bin/ is the *nix directory, the second item is for 'cmd /param1 etc.' (Windows)

	function logAttack($msg) {
		//Check if any attack log file exists
		if (!file_exists($this->LOG_FILEPATH)) {
			//Create a new log file
			$logs = fopen($this->LOG_FILEPATH, "w");
			if ($this->LOG_PASSWORD == "")
				$this->LOG_PASSWORD = substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789'),0,8); //Generate random password
			$auth_header = "<?php include '" . $this->LITEWAF_PATH . "litewaf.php'; if(isset(\$_GET['pwd']) && (\$_GET['pwd'] == \"" . $this->LOG_PASSWORD . "\")) { header('Content-Type:text/plain'); } else ";
			if ($this->LOG_REDIRECT) {
				$auth_header .= "{ header('Location: /" . $this->REDIRECT_PAGE . "', true, 302); die(''); } ?>";
			} else {
				$auth_header .= "{ die(\"Not Authorized\"); } ?>";
			}
			fwrite($logs, $auth_header);
			fclose($logs);
		}
		$logs = fopen($this->LOG_FILEPATH, "a+");
		$ipAddress = $_SERVER['REMOTE_ADDR'];
		if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
			$ipAddress = array_pop(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
		}
		$content = htmlentities(date('d-m-Y H:i:s') . "\tIP: " . $ipAddress . "\tMethod: " . $_SERVER['REQUEST_METHOD'] . "\tURL: " . $_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"] . "\tUser-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\tAttack Type: " . $msg . "\tProduct: " . $this::PRODUCT . " " . $this::VERSION) . "\r\n";
		fwrite($logs, $content);
		fclose($logs);
	}

	function warn($msg) {
		//Log the message
		$this->logAttack($msg);
		//Redirect the user
		$this->redirect();
	}
	
	function lookForMarkers($arr_markers, $str) {
		//This function checks if one of the markers is contained in the input string	
		foreach ($arr_markers as $marker) {
			if (strpos($str, $marker) !== false) {
				return true;
			}
		}
		return false;
	}
	
	function checkParameter($key, $value) {
		if (is_array($value)) {
			if (!$this->ALLOW_ARRAYS) {
				//log the event
				$this->warn("User passed an array as input for parameter '" . $key ."'");
				unset($key);
				return;	
			} else {
				//Attention: Arrays are currently unsupported!!!
				return;
			}
		}
		//Decode eventually encoded parameter
		$value = html_entity_decode($value);
		//Normalize the value
		$value = str_replace(" ", "", strtolower($value));
		//Compare the param to the blacklists
		if ($this->lookForMarkers($this->sqli_markers, $value))
			$this->warn("SQL Injection");
		elseif ($this->lookForMarkers($this->xss_markers, $value))
			$this->warn("XSS");
		elseif ($this->lookForMarkers($this->pathtraversal_markers, $value))
			$this->warn("Path Traversal");
		elseif ($this->lookForMarkers($this->rce_markers, $value))
			$this->warn("Remote Command Execution");
	}

	function redirect() {
		header("Location: /" . $this->REDIRECT_PAGE, true, 302);
		die(""); //Prevent page loading
	}

	function run() {
		if ($_SERVER['REQUEST_METHOD'] === 'GET') {
			//Check GET parameters
			foreach ($_GET as $key => $value) {
				$this->checkParameter($key, $value);
			}
		} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
			//Check POST parameters
			foreach ($_POST as $key => $value) {
				$this->checkParameter($key, $value);
			}
		}
	}
}

$litewaf = new LiteWAF;
$litewaf->run();

//Check if LiteWAF script is loaded directly instead of to be included
if (realpath(__FILE__) == realpath($_SERVER['DOCUMENT_ROOT'].$_SERVER['SCRIPT_NAME'])) {
	$litewaf->redirect();
}
?>

