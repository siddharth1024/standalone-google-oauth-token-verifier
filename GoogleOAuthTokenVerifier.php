<?php

/**
 * Standalone Google OAuth2 Token Verifier
 * User: siddharth1024 / sidx1024
 * Github : https://github.com/siddharth1024
 *
 * Contains code from Google OAuth2 libraries, however this doesn't connect to Google Servers for token verification.
 * Create an object of this class and call verifyToken(ID_TOKEN), where ID_TOKEN is token received from client/user.
 * 
 */

use Firebase\JWT\JWT as JWT;
use Firebase\JWT\ExpiredException as ExpiredException;
use Firebase\JWT\ExpiredException as ExpiredExceptionV3;
use phpseclib\Crypt\RSA as RSA;
use phpseclib\Math\BigInteger as BigInteger;

class GoogleOAuthTokenVerifier
{
    
    private $audience = ""; // TODO : Add your google client id here
    const OAUTH2_ISSUER = 'accounts.google.com';
    const OAUTH2_ISSUER_HTTPS = 'https://accounts.google.com';
    const GOOGLE_CERTIFICATES = [
        'keys' => [
            [
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'kid' => '15fe11faa746a82b16ce3fd80954022e0189ca96',
                'n' => 'pWF7x86bxxCoj0eiwelPCBgbbgW2cpL155m7K0mJvdmObJz35ecgQMsiXRixApmNO28rDh7Tyc3bTTz4QARoQGFar9QKcE8LI7SPnKqtzah2CHz5Nqn6u-Jj8kVIEnmHZMaXjt3nFChb028WTpsG0ZpIGH29v5nBX1RC4EwNTE6YMJWwsrMJkEuJezSdKvL6jYMJU9Doxb7cxRj2K_Kj5h_nnOtJ5Myd9DFzj8waOsaxk7WlJHt98Oe18D90P4hOiusiP_g31cBQ7SF5zIh3qHdlku7Knm2KCF9J6nSt4dCIRlD2yuKLLBtEacVti6jpmkmKyChiRsZMa-jkKGd9iQ',
                'e' => 'AQAB'
            ],
            [
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'kid' => 'b6e2d0fc85b5df47471e638a0fb7f3acdc5b2484',
                'n' => 'kzs8fYVlvua_1yR66h4DtmEHr44crdiRCDbjAVSL2SA0DcGrHOloqEWPGXRba_dGXox0DmQMfY-5LCdsLxJ7ukciTHFs0gwoP8LSR07ZEcApIbbP0IG073FnCOPuSqSxaOG47YPxHDwPsVXH6qKkhjAwPzW3r2kvDZMWxN7IWtpiyf-tpmPE_cRYw8rr_KL8MPmubAnifRdIT-92FkrOkxsA-gINZxy1-iatT7I0IUZZO4n_uDSC2KSHcpIbPTbVa_Km6aRMltKXhj-GUpavvJtR4KSTS5f8Wj-DmVLmG_g7wDiwbZpQtJv93BkhAT0kRoFCt1MUshhLYMFjsKYcvw',
                'e' => 'AQAB'
            ],
            [
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'kid' => '2064f09183b8048f881ea6f0336bd8a98edbae9d',
                'n' => '0mG0fRQAv7ponetyaI3kxjTLBBikLnuFcFeZmyXWx6Aow84N2_qVYgMbjb2HRULSpzc2pWOnm9j4uO18kznqqkhm1cIzXNYXBzcr0-XFyGb_TjDl5sbLfQQ01LY3r1r45eVqxH0kr4bcz02ToZWAkNhRRg8W8Oo6VilWQ509iwdJ81vYAHRB8VslzSJ-OemSDC0wJLlfWhZAdJMhi7iqVGeX9B9vRNCXn18Y3oWRJXzBZx2lb-TrgclbcPdfaN_8VJqqZAJ1jjUEzMA9GahBRO53Cg7aO3zq3R6S-g-6RacsvqErl9p5gtBpVzAYq3q4DX51JzXknqpxsrFMlene9Q',
                'e' => 'AQAB'
            ]
        ]
    ];

    public function verifyToken($idToken)
    {
        if (empty($idToken)) {
            throw new LogicException('id_token cannot be null');
        }
        $audience = $this->audience;
        $certs = self::GOOGLE_CERTIFICATES['keys'];

        foreach ($certs as $cert) {
            $jwt = new JWT;
            $modulus = new BigInteger($jwt->urlsafeB64Decode($cert['n']), 256);
            $exponent = new BigInteger($jwt->urlsafeB64Decode($cert['e']), 256);

            $rsa = new RSA;
            $rsa->loadKey(array('n' => $modulus, 'e' => $exponent));

            try {
                $payload = $jwt->decode(
                    $idToken,
                    $rsa->getPublicKey(),
                    array('RS256')
                );

                if (property_exists($payload, 'aud')) {
                    if ($audience && $payload->aud != $audience) {
                        return false;
                    }
                }

                $issuers = array(self::OAUTH2_ISSUER, self::OAUTH2_ISSUER_HTTPS);
                if (!isset($payload->iss) || !in_array($payload->iss, $issuers)) {
                    return false;
                }

                return (array)$payload;

            } catch (ExpiredException $e) {
                return false;
            } catch (DomainException $e) {
                // continue
            }
        }
        return false;
    }
}