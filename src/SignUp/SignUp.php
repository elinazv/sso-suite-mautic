<?php
namespace SignUp;

use OneLogin\api\OneLoginClient;
use Mautic\MauticApi;
use Ramsey\Uuid\Uuid;
use OneLogin\api\models\User as OneLogin_User;
use OneLogin\api\models\Role as OneLogin_Role;
use OneLogin\api\models\SessionTokenInfo;
use Psr\Log\LoggerInterface;
use Validation\Validator;
use Oauth2\Oauth2TokenFactory;
use Oauth2\Oauth2TokenRepository;

class SignUp
{
    /**
     * @var Validator
     */
    private $validator;

    /**
     * @var
     */
    private $oneloginClient;

    /**
     * @var \Oauth2\Oauth2TokenRepository
     */
    private $repository;

    /**
     * @var \Oauth2\Oauth2TokenFactory
     */
    private $factory;

    /**
     * @var
     */
    private $logger;

    /**
     * @var
     */
    private $settings;

    public function __construct(array $settings)
    {
        $this->validator = new Validator();

        $this->settings = $settings;

        $this->repository = new Oauth2TokenRepository($this->settings['home_db']);
        $this->factory = new Oauth2TokenFactory();
    }

    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    private function createOneLoginClient()
    {
        if (!isset($this->oneloginClient)) {
            /*if (!isset($_SERVER['CLIENT_SECRET'])) {
                throw new SignUpException('No client secret');
            }

            if (!isset($_SERVER['CLIENT_ID'])) {
                throw new SignUpException('No client id');
            }*/

            $this->oneloginClient = new OneLoginClient(
                $this->settings['onelogin']['clientId'],
                $this->settings['onelogin']['clientSecret']);
        }
    }

    public function login()
    {
        $this->createOneLoginClient();

        $this->logger->log('debug', 'oneloginClient: ' . get_class($this->oneloginClient));

        if (empty($_POST['username'])) {
            throw new SignUpException('No user name');
        }

        if (empty($_POST['password'])) {
            throw new SignUpException('No password');
        }

        $sessionLoginTokenParams = [
            "username_or_email" => $_POST['username'],
            "password" => $_POST['password'],
            "subdomain" => $this->getSubdomain()
        ];

        $sessionTokenData = $this->oneloginClient->createSessionLoginToken($sessionLoginTokenParams, 'http://' . $_SERVER['SERVER_NAME']);

        if (!$sessionTokenData instanceof SessionTokenInfo) {
            throw new SignUpException('Login or/and Password not correct');
        } else {
            return $sessionTokenData;
        }
    }

    private function getSubdomain()
    {
        $array = parse_url($this->settings['idp']['singleSignOnService']['url']);
        $array['host'] = explode('.', $array['host']);

        return $array['host'][0];
    }

    public function loginApp()
    {
        $this->createOneLoginClient();

        $this->logger->log('debug', 'oneloginClient: ' . get_class($this->oneloginClient));

        $sessionLoginTokenParams = [
            "username_or_email" => $_SERVER['username'],
            "password" => $_SERVER['password'],
            "subdomain" => $this->getSubdomain()
        ];

        $sessionTokenData = $this->oneloginClient->createSessionLoginToken($sessionLoginTokenParams, 'http://' . $_SERVER['SERVER_NAME']);

        if (!$sessionTokenData instanceof SessionTokenInfo) {
            throw new SignUpException('Login or/and Password not correct');
        } else {
            return $sessionTokenData;
        }
    }

    public function getOneLoginRoles()
    {
        $this->createOneLoginClient();

        //$this->logger->log('debug', 'parameter: ' . print_r($parameter, true));

        $this->logger->log('debug', 'oneloginClient: ' . get_class($this->oneloginClient));

        $roles = $this->oneloginClient->getRoles();

        $this->logger->log('debug', '$roles: ' . print_r($roles, true));

        return $roles;
    }

    public function getOneLoginDefaultRole()
    {
        $this->createOneLoginClient();

        $this->logger->log('debug', 'oneloginClient: ' . get_class($this->oneloginClient));

        $roles = $this->oneloginClient->getRoles(['name' => 'Default']);

        $this->logger->log('debug', '$roles: ' . print_r($roles, true));

        if (!is_array($roles) || empty($roles)) {
            $this->logger->log('debug', 'no roles with name default');
            throw new SignUpException('No default Role in Onelogin.');
        }

        foreach ($roles as $role)
        {

            if (!$role instanceof OneLogin_Role) {
                $this->logger->log('debug', 'role is not valid');
                throw new SignUpException('Role in Onelogin with given parameter couldn\'t be found.');
            }

            if ($role->getName() == 'Default') {
                $this->logger->log('debug', 'default role: ' . print_r($role, true));
                return $role;
            }

        }
    }

    public function setDefaultRoleForUserInOnelogin($userId, $roleId)
    {
        $this->createOneLoginClient();

        $this->logger->log('debug', 'oneloginClient: ' . get_class($this->oneloginClient));

        if (empty($userId)) {
            throw new SignUpException('No user id');
        }

        if (empty($roleId)) {
            throw new SignUpException('No role id');
        }

        /* Assign & Remove Roles On Users */
        $newRoleIds = array(
            $roleId
        );

        $result = $this->oneloginClient->assignRoleToUser($userId, $newRoleIds);

        if (!$result) {
            throw new SignUpException("Role $roleId for User $userId in Onelogin couldn't be assigned.");
        }

        return $result;
    }

    public function createUserOneLogin($parameter = array())
    {
        $this->createOneLoginClient();

        $this->logger->log('debug', 'parameter: ' . print_r($parameter, true));

        $this->logger->log('debug', 'oneloginClient: ' . get_class($this->oneloginClient));

        $createdUser = $this->oneloginClient->createUser($parameter);

        $this->logger->log('debug', '$createdUser: ' . print_r($createdUser, true));

        if (!$createdUser instanceof OneLogin_User) {
            throw new SignUpException('User in Onelogin couldn\'t be created');
        }
        return $createdUser;

    }

    public function setPasswordForUserOneLogin($userId, $password)
    {
        $this->createOneLoginClient();

        $this->logger->log('debug', 'oneloginClient: ' . get_class($this->oneloginClient));

        $this->logger->log('debug', 'access token: ' . print_r($this->oneloginClient->getAccessToken(), true));

        $this->logger->log('debug', 'token: ' . $this->oneloginClient->getAccessToken()->getAccessToken());


        if (!$userId) {
            throw new SignUpException("No User ID for new created user in Onelogin");
        }
        if (!$password) {
            throw new SignUpException("No password given for creating user in Onelogin");
        }
        try {
            $result = $this->oneloginClient->setPasswordUsingClearText($userId, $password, $password);

            if (!$result) {
                throw new SignUpException("Password for new created user couldn't be set in Onelogin");
            }

            $this->logger->log('debug', 'result: ' . print_r($result, true));

            return $result;
        } catch (\Exception $e)
        {

            $this->logger->log('debug', $e->getMessage());

            $this->logger->log('debug', get_class($e) );
        }

        if (!$result) {
            throw new SignUpException("Password for user with $userId Onelogin couldn't be created");
        }

    }


    public function createUserMautic($userParameters)
    {
        /*if (!isset($_SERVER['MAUTIC_BASE_URL'])) {
            throw new SignUpException('No mautic base url');
        }

        if (!isset($_SERVER['MAUTIC_CLIENT_KEY'])) {
            throw new SignUpException('No mautic client key');
        }

        if (!isset($_SERVER['MAUTIC_CLIENT_SECRET'])) {
            throw new SignUpException('No mautic client secret');
        }*/

        // ApiAuth->newAuth() will accept an array of Auth settings
        $settings = array(
            'baseUrl'          => $this->settings['mautic']['base_url'],       // Base URL of the Mautic instance
            'version'          => 'OAuth2', // Version of the OAuth can be OAuth2 or OAuth1a. OAuth2 is the default value.
            'clientKey'        => $this->settings['mautic']['clientKey'],       // Client/Consumer key from Mautic
            'clientSecret'     => $this->settings['mautic']['clientSecret'],       // Client/Consumer secret key from Mautic
            'callback'         => $_SERVER["SERVER_NAME"] . '/mautic'        // Redirect URI/Callback URI for this script
        );

        $oauth2Token = $this->repository->getToken('mautic');

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . ' : ' . print_r($oauth2Token, true));

        $auth = $this->factory->createMauticAuth($oauth2Token, $settings);

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . ' auth class: ' . get_class($auth));

        $auth->enableDebugMode();

        // Initiate the auth object
        //$initAuth = new ApiAuth();
        //$auth = $initAuth->newAuth($settings);

        // Initiate process for obtaining an access token; this will redirect the user to the $authorizationUrl and/or
        // set the access_tokens when the user is redirected back after granting authorization

        // If the access token is expired, and a refresh token is set above, then a new access token will be requested


        if ($auth->validateAccessToken()) {

            $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ );

            // Obtain the access token returned; call accessTokenUpdated() to catch if the token was updated via a
            // refresh token

            // $accessTokenData will have the following keys:
            // For OAuth1.0a: access_token, access_token_secret, expires
            // For OAuth2: access_token, expires, token_type, refresh_token

            if ($auth->accessTokenUpdated()) {
                $accessTokenData = $auth->getAccessTokenData();

                $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . ' : ' . print_r($accessTokenData, true));

                $oauth2Token = $this->factory->createOauth2TokenFromMauticToken($accessTokenData);

                $this->repository->saveToken($oauth2Token);


            }
        }

        $api = new MauticApi();
        $apiUrl = $settings['baseUrl'] . '/api';
        $userApi = $api->newApi('users', $auth, $apiUrl);

        $responseCreatingUser = $userApi->create(
            $userParameters
        );

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . ' create contact response: ' . print_r($responseCreatingUser, true));

        /*$contactApi = $api->newApi('contacts', $auth, $apiUrl);

        $contactParameter = [
            'firstname' => $userParameters['firstName'],
            'lastname' => $userParameters['lastName'],
            'email' => $userParameters['email'],
            'suite_id' => 'NOT_PRESENT' . Uuid::uuid1()
        ];

        $responseCreatingContactForUser = $contactApi->create(
            $contactParameter
        );

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ . ' create contact response: ' . print_r($responseCreatingContactForUser, true));*/
        return $responseCreatingUser;

    }

    /**
     * @return Validator
     */
    public function getValidator()
    {
        return $this->validator;
    }


    public function createUserSuite()
    {
        session_start();

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__ );

        $provider = new \SignUp\MyProvider([
                'clientId'                => $this->settings['suite']['clientId'],    // The client ID assigned to you by the provider
                'clientSecret'            => $this->settings['suite']['clientSecret'],   // The client password assigned to you by the provider
                'grant_type'              => 'client_credentials',
                'urlAuthorize'            => $this->settings['suite']['base_url'] . '/index.php?module=OAuthTokens&action=authorize',
                'urlAccessToken'          => $this->settings['suite']['base_url'] . '/Api/access_token',
                'urlResourceOwnerDetails' => $this->settings['suite']['base_url'] .  '/Api/V8/current-user'
            ],
            [],
            $this->logger
        );

        $oauth2Token = $this->repository->getToken('suite');

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' : ' . print_r($oauth2Token, true));


        if ($oauth2Token instanceof \Oauth2\Oauth2Token) {

            //create AccessToken from Oauth2Token
            $accessToken =  $this->factory->createSuiteAccessTokenFromOauth2Token($oauth2Token);

            $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' : ' . print_r($accessToken, true));

        } else {

            /*$client = new GuzzleHttp\Client();
            $res = $client->request('POST', $_SERVER['SUITE_BASE_URL'] . '/Api/access_token', ['multipart' => [
                [
                    'grant_type'     => 'client_credentials',
                    'client_id' => $_SERVER['SUITE_CLIENT_ID'],
                    'client_secret' => $_SERVER['SUITE_CLIENT_SECRET']
                ]
            ]]);

            var_dump($res);exit;*/


            // Try to get an access token using the authorization code grant.
            $accessToken = $provider->getAccessToken('client_credentials', [
                //            'code' => $_GET['code']
                "scopes"=> "standard:create standard:read standard:update standard:delete standard:delete standard:relationship:create standard:relationship:read standard:relationship:update standard:relationship:delete"
            ]);

            $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' : ' . print_r($accessToken, true));
            $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' access token: ' . $accessToken->getToken() .
                ' refresh token: ' . $accessToken->getRefreshToken() .
                ' token expires: ' . $accessToken->getExpires() .
                ' token : ' . ($accessToken->hasExpired() ? 'expired' : 'not expired'));
            $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' : ' . $accessToken->getRefreshToken());
            $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' : ' . $accessToken->getExpires());
            $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' : ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') );

            $oauth2Token = $this->factory->createOauth2TokenFromSuiteToken($accessToken);

            $this->repository->saveToken($oauth2Token);
        }

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' access token: ' . $accessToken->getToken() .
            ' refresh token: ' . $accessToken->getRefreshToken() .
            ' token expires: ' . $accessToken->getExpires() .
            ' token : ' . ($accessToken->hasExpired() ? 'expired' : 'not expired'));

        if ($accessToken->hasExpired()) {
            $newAccessToken = $provider->getAccessToken('client_credentials', [
                //            'code' => $_GET['code']
                "scopes"=> "standard:create standard:read standard:update standard:delete standard:delete standard:relationship:create standard:relationship:read standard:relationship:update standard:relationship:delete"
            ]);

            $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' : ' . print_r($newAccessToken, true));

            $oauth2Token = $this->factory->createOauth2TokenFromSuiteToken($newAccessToken);

            $this->repository->saveToken($oauth2Token);

            // Purge old access token and store new access token to your data store.
            $accessToken = $newAccessToken;
        }

        $bodyParameters = [
            'data' =>
                [
                    "type" => "Users",
                    "id" => Uuid::uuid1(),
                    "attributes" => [
                        "user_name" => $_POST['email'],
                        "first_name" => $_POST['firstname'],
                        "last_name" => $_POST['lastname'],
                        "user_hash" => $_POST['password'],
                        "email1" => $_POST['email'],
                        "external_auth_only" => 1,
                        "mautic_id_c" => $_POST['mautic_id_c'],
                        "aclroles" => "API Registered",
                        "status" => "Active"
                    ]
                ]
        ];

        $body = json_encode($bodyParameters);

        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' body parameter: ' . $body);


        $request = $provider->getAuthenticatedRequest(
            'POST',
            $this->settings['suite']['base_url'] . '/Api/V8/module',
            $accessToken,
            [
                'body' => $body,
                'headers' => [
                    'content-type' => 'application/json',
                    'accept' => 'application/vnd.api+json'
                ]
            ]
        );

        $response = $provider->getParsedResponse($request);
        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' : ' . print_r($response, true));

        $bodyParameters = [
            'data' =>
                [
                    "type" => "Users",
                    "id" => $response['data']['id'],

                ]
        ];

        $body = json_encode($bodyParameters);

        $request = $provider->getAuthenticatedRequest(
            'POST',
            $this->settings['suite']['base_url'] . '/Api/V8/module/ACLRole/3823d083-8118-ec11-a280-5c52d04ab0df/relationships',
            $accessToken,
            [
                'body' => $body,
                'headers' => [
                    'content-type' => 'application/json',
                    'accept' => 'application/vnd.api+json'
                ]
            ]
        );

        $response = $provider->getParsedResponse($request);
        $this->logger->log('debug', __METHOD__ . ' : ' . __LINE__  . ' : ' . print_r($response, true));

    }

}