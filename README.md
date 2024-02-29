[![PHPCSFixer](https://github.com/danielburger1337/oauth2-dpop-php/actions/workflows/phpcsfixer.yml/badge.svg)](https://github.com/danielburger1337/oauth2-dpop-php/actions/workflows/phpcsfixer.yml)
[![PHPStan](https://github.com/danielburger1337/oauth2-dpop-php/actions/workflows/phpstan.yml/badge.svg)](https://github.com/danielburger1337/oauth2-dpop-php/actions/workflows/phpstan.yml)
[![PHPUnit](https://github.com/danielburger1337/oauth2-dpop-php/actions/workflows/phpunit.yml/badge.svg)](https://github.com/danielburger1337/oauth2-dpop-php/actions/workflows/phpunit.yml)
![Packagist Version](https://img.shields.io/packagist/v/danielburger1337/oauth2-dpop?link=https%3A%2F%2Fpackagist.org%2Fpackages%2Fdanielburger1337%2Foauth2-dpop)
![Packagist Downloads](https://img.shields.io/packagist/dt/danielburger1337/oauth2-dpop?link=https%3A%2F%2Fpackagist.org%2Fpackages%2Fdanielburger1337%2Foauth2-dpop)

# oauth2-dpop

A PHP 8.2+ library that helps you both create and/or verify [OAuth2 DPoP](https://datatracker.ietf.org/doc/html/rfc9449) proof tokens.

> Demonstrating Proof of Possession (DPoP) is an application-level mechanism for sender-constraining OAuth [RFC6749] access and refresh tokens. It enables a client to prove the possession of a public/private key pair by including a DPoP header in an HTTP request. The value of the header is a JSON Web Token (JWT) [RFC7519] that enables the authorization server to bind issued tokens to the public part of a client's key pair. Recipients of such tokens are then able to verify the binding of the token to the key pair that the client has demonstrated that it holds via the DPoP header, thereby providing some assurance that the client presenting the token also possesses the private key. In other words, the legitimate presenter of the token is constrained to be the sender that holds and proves possession of the private part of the key pair.<br>
> ~ [Section 1 of RFC-9449](https://datatracker.ietf.org/doc/html/rfc9449#section-1)

## Install

This library is [PSR-4](https://www.php-fig.org/psr/psr-4/) compatible and can be installed via PHP's dependency manager [Composer](https://getcomposer.org).

```shell
composer require danielburger1337/oauth2-dpop
```

## Documentation

You can find the documentation [here](docs/README.md).

## Running Tests Locally

This library is fully unit tested. It also uses strict static analysis to minimize the possibility of unexpected runtime errors.

```sh
composer install

vendor/bin/php-cs-fixer fix
vendor/bin/phpstan
vendor/bin/phpunit
```

## License

This software is available under the [MIT](LICENSE) license.
