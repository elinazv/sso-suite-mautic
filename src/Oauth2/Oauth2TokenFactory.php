<?php

namespace Oauth2;

use Ramsey\Uuid\UuidInterface;
use League\OAuth2\Client\Token\AccessToken as SuiteToken;
use OneLogin\api\models\OneLoginToken;
use Mautic\Auth\ApiAuth;

class Oauth2TokenFactory
{
    public static function createOauth2TokenFromSuiteToken(SuiteToken $token)
    {
        $data = [
            'provider' => 'suite',
            'accessToken' => $token->getToken(),
            'accessTokenExpires' => $token->getExpires()

        ];

        $oauth2Token = new Oauth2Token($data);

        return $oauth2Token;
    }


    public static function createOauth2TokenFromMauticToken($token = [])
    {
        $data = [
            'provider' => 'mautic',
            'accessToken' => $token['access_token'],
            'accessTokenExpires' => $token['expires'],
            'refreshToken' => $token['refresh_token']

        ];

        $oauth2Token = new Oauth2Token($data);

        return $oauth2Token;
    }

    public static function createOauth2TokenFromOneloginToken(OneLoginToken $token)
    {
        $data = [
            'provider' => 'onelogin',
            'accessToken' => $token->getAccessToken(),
            'accessTokenExpires' => $token->getExpiration()->getTimestamp(),
            'refreshToken' => $token->getRefreshToken(),
            'createdAt' => $token->getCreatedAt()->getTimestamp(),
            'accountId' => $token->getAccountId(),
            'type' => $token->getTokenType()

        ];

        $oauth2Token = new Oauth2Token($data);

        return $oauth2Token;
    }

    public static function createSuiteAccessTokenFromOauth2Token(Oauth2Token $oauth2Token)
    {
        $accessToken = new SuiteToken(
            [
                'access_token' => $oauth2Token->getAccessToken(),
                'refresh_token' => $oauth2Token->getRefreshToken(),
                'expires' => $oauth2Token->getAccessTokenExpires()
            ]
        );

        return $accessToken;
    }

    public static function createOneLoginTokenFromOauth2Token(Oauth2Token $oauth2Token)
    {
        $data = new stdClass();
        $data->access_token = $oauth2Token->getAccessToken();
        $data->refresh_token = $oauth2Token->getRefreshToken();
        $accountId = $oauth2Token->getAccountId();
        $data->account_id = isset($accountId)? (int)$accountId: 0;
        $tokenType = $oauth2Token->getTokenType();
        $data->token_type = isset($tokenType)? $tokenType: '';
        $utc = new \DateTimeZone("UTC");
        $data->created_at = \DateTime::createFromFormat('Y-m-d\TH:i:s+', $oauth2Token->getCreatedAt(), $utc);
        $data->expires_in = $oauth2Token->getAccessTokenExpires() - $oauth2Token->getCreatedAt();

        $oneLoginToken = new OneLoginToken($data);

        return $oneLoginToken;
    }

    public static function createMauticAuth(Oauth2Token $oauth2Token = null, $settings = [])
    {
        //Check if refresh token could have expired by 2 weeks
        if (isset($oauth2Token) && $oauth2Token->getCreatedAt() > strtotime('-2 weeks')) {
            $settings['accessToken']        = $oauth2Token->getAccessToken();
            $settings['accessTokenExpires'] = $oauth2Token->getAccessTokenExpires(); //UNIX timestamp
            $settings['refreshToken']       = $oauth2Token->getRefreshToken();
        }

        $initAuth = new ApiAuth();
        $auth = $initAuth->newAuth($settings);
        return $auth;
    }
}