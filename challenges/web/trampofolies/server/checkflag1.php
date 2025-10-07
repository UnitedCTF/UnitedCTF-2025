<?php
$image_path = "/var/www/html/images/thumb/f/fc/Trampolin.png/500px-Trampolin.png";

if(file_exists($image_path)) {
    echo "L'image problématique est toujours sur le site.<br>Emplacement de l'image: $image_path";
} else {
    echo "Vive les trampolineux! ";
    passthru("/printflag1");
}
?>