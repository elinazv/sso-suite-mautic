<?php
namespace Oauth2;

use Ramsey\Uuid\UuidInterface;

/**
 * @Entity
 * @Table(name="oauth2_tokens")
 */
class Oauth2Token
{
    /**
     * @var \Ramsey\Uuid\UuidInterface
     *
     * @Id
     * @Column(type="uuid", unique=true, name="id")
     * @GeneratedValue(strategy="CUSTOM")
     * @CustomIdGenerator(class="Ramsey\Uuid\Doctrine\UuidGenerator")
     */
    private $uuid;

    /**
     * @Column(type="string", name="access_token")
     */
    private $accessToken;

    /**
     * @Column(type="string", name="refresh_token")
     */
    private $refreshToken;

    /**
     * @Column(type="integer", name="access_token_expires")
     */
    private $accessTokenExpires;

    /** @Column(type="string") */
    private $provider;

    /** @Column(type="integer", name="account_id") */
    private $accountId;

    /**
     * @Column(type="string", name="token_type")
     */
    private $tokenType;

    /**
     * @Column(type="integer", name="created_at")
     */
    private $createdAt;

    public function __construct($data = [])
    {
        $this->accessToken = $data['accessToken'];
        $this->provider = $data['provider'];
        $this->accessTokenExpires = $data['accessTokenExpires'];
        $this->createdAt = isset($data['createdAt'])? $data['createdAt']: time();
        if (isset($data['refreshToken'])) {
            $this->refreshToken = $data['refreshToken'];
        }
        if (isset($data['accountId'])) {
            $this->accountId = $data['accountId'];
        }
        if (isset($data['tokenType'])) {
            $this->tokenType = $data['tokenType'];
        }
    }

    /**
     * @return mixed
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * @return mixed
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * @return mixed
     */
    public function getAccessTokenExpires()
    {

        return $this->accessTokenExpires;
    }

    /**
     * @return mixed
     */
    public function getCreatedAt()
    {
        return $this->createdAt;
    }




}