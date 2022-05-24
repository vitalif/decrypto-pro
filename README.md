# decrypto-pro

Конвертирует ГОСТ Р 34.11-94 и ГОСТ Р 34.11-2012 закрытые ключи из упоротого формата Крипто-Про (Криво-Про) в нормальный PEM (OpenSSL) формат.

Почти копия https://github.com/kulikan/privkey, изначально основано на https://habrahabr.ru/post/275039/

Лицензия MIT

## Установка

Для сборки требует OpenSSL 1.1 и установленный ГОСТ движок:

```
apt-get install libengine-gost-openssl1.1 libssl-dev

make
```

Работает в Debian. В других дистрибутивах нужно будет поправить Makefile.

## Конвертация

Конвертация ключа:

* `./decrypto-pro /path/to/key/dir.000 > privkey.pem`

Конвертация сертификата:

* Копируем директорию ключевого контейнера в `/var/opt/cprocsp/keys/<USER>`, где `<USER>` - имя системного пользователя (`id -un`).
* `/opt/cprocsp/bin/amd64/certmgr -export -dest cert.der` и вводим номер нужного сертификата в списке
* `openssl x509 -inform DER -in cert.der -out cert.pem` - конвертируем из бинарного формата в привычный PEM

## Примеры использования

Подпись PKCS-7 (вместо `openssl smime` можно также писать `openssl cms`):

`openssl smime -sign
    -in пример.pdf -out пример_подпись.p7s
    -engine gost -binary -noattr -outform der
    -signer cert.pem -inkey privkey.pem`

Проверка подписи:

`openssl smime -verify
    -content пример.pdf -in пример_подпись.p7s
    -engine gost -binary -noattr -inform der
    -CAfile CA.pem -signer cert.pem`

## Ещё заметки

Зашифровать приватный ключ:

`openssl pkey -in privkey.pem -out privkey_enc.pem -aes256`

Наоборот, импортировать приватный ключ PEM (openssl) в Крипто-Про - увы,
можно только через PFX и утилиту p12util, скачать которую можно где-то на их форумах.
Благо, под wine она тоже работает:

`openssl pkcs12 -inkey privkey.pem -in cert.pem -keypbe gost89 -certpbe gost89 -macalg md_gost12_512 -export -out cert_and_key.pfx`

`wine p12util.x86.exe -p12tocp -infile cert_and_key.pfx -rdrfolder Z:/var/opt/cprocsp/keys -contname Новое_Имя_Ключа -ex -passcp '' -passp12 ''`

`/opt/cprocsp/bin/amd64/certmgr -install -container '\\.\HDIMAGE\Новое_Имя_Ключа'`

Установить корневой сертификат (CA) в Криво-Про, чтобы оно не ругалось при подписи из браузерного плагина:

`/opt/cprocsp/bin/amd64/certmgr -install -store root -file CA.crt`

## Идея вам на будущее

Сделать опенсорсный браузерный плагин, работающий на основе openssl и совместимый с JS-интерфейсом плагина КриптоПро.
