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

## Пример использования

Подпись:

`openssl cms -sign -inkey private.key -in file.txt -CAfile CA.cer -signer signer.cer -engine gost -out file.txt.sgn -outform DER -noattr -binary`

Проверка подписи:

`openssl cms -verify -content file.txt -in file.txt.sgn -CAfile CA.cer -signer signer.cer -engine gost -inform DER -noattr -binary`

## Идея вам на будущее

Сделать опенсорсный браузерный плагин, работающий на основе openssl и совместимый с JS-интерфейсом плагина КриптоПро.
