<?php

namespace SignUp;

use League\OAuth2\Client\Provider\GenericProvider;


class MyProvider extends GenericProvider
{


    /**
     * MyProvider constructor.
     */
    public function __construct(array $options = [], array $collaborators = [], $logger = null)
    {
        $this->logger = $logger;
        parent::__construct($options, $collaborators);
    }

    public function getAccessToken($grant, array $options = [])
    {
        $grant = $this->verifyGrant($grant);

        $params = [
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUri,
        ];

        $params   = $grant->prepareRequestParameters($params, $options);
        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ );

        $request  = $this->getAccessTokenRequest($params);
        $response = $this->getParsedResponse($request);
        if (false === is_array($response)) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }
        $prepared = $this->prepareAccessTokenResponse($response);
        $token    = $this->createAccessToken($prepared, $grant);

        return $token;
    }

    protected function getAccessTokenRequest(array $params)
    {
        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . 'params:: ' . print_r($params, true));

        $method  = $this->getAccessTokenMethod();
        $url     = $this->getAccessTokenUrl($params);

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ );

        $accessTokenMethod = $this->getAccessTokenMethod();

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . ' $accessTokenMethod:: ' . $accessTokenMethod);

        $options = $this->optionProvider->getAccessTokenOptions($this->getAccessTokenMethod(), $params);

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . ' $options:: ' . print_r($options, true));

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . ' url:: ' . $url . ' method:: ' . $method);

        $request = $this->getRequest($method, $url, $options);

        var_dump($request);

        return $request;
    }

    protected function createRequest($method, $url, $token, array $options)
    {
        $defaults = [
            'headers' => $this->getHeaders($token),
        ];

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . ' defaults:: ' . print_r($defaults, true));

        $options = array_merge_recursive($defaults, $options);

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . ' defaults:: ' . print_r($options, true));

        $factory = $this->getRequestFactory();

        $r = $factory->getRequestWithOptions($method, $url, $options);

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . ' request:: ' . print_r($r, true));

        return $r;
    }

    protected function getDefaultHeaders()
    {
        return ['port' => 80, 'scheme' => 'http'];
    }
}