# JKT Check-In Kiosk

## Write-up

Le binaire (glibc 2.31) propose une borne d'enregistrement avec 3 actions. Les options **1** et **3** effectuent **une seule lecture non bornée dans une structure `FILE`** allouée par le programme (`fopen("/dev/null", "r"/"w")`).

**Arbitrary write via `fread` — option 1**
```
fp->_flags       = 0x0
fp->_IO_buf_base = &is_premium
fp->_IO_buf_end  = &is_premium + 0x101
fp->_fileno      = 0
```
On force la lecture via le chemin `fread → _IO_file_xsgetn → __underflow → _IO_new_file_underflow`, ce qui lit **depuis `stdin` directement dans `is_premium`**.  
En envoyant `\x01`, on passe `is_premium` à `1`.

**Chargement du flag — option 2**  
Avec `is_premium == 1`, le programme lit `/tmp/flag.txt` dans le buffer global `win`.

**Arbitrary read/print via `fwrite` — option 3**
```
fp->_flags        = 0x0800
fp->_IO_write_base= &win
fp->_IO_write_ptr = &win + 60
fp->_IO_write_end = &win
fp->_fileno       = 1
```
Le flush forcé dans la chaîne `fwrite → _IO_file_xsputn → _IO_do_write` déclenche un `write(1, &win, 0x3c)` → fuite du flag.

Le code de la [solution](solution.py).

## Flag
`flag-wu92phofpc78upd9`
