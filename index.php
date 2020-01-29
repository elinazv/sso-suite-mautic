<?php
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Kernel as BaseKernel;
use Symfony\Component\Routing\RouteCollectionBuilder;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Route;
use Symfony\Component\Yaml\Yaml;

use SignUp\SignUp;
use SignUp\SignUpException;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Utils;
use Cookies\CookiesRepository;

header("Access-Control-Allow-Origin: *");
header("Access-Control-Request-Method: *");
header("Access-Control-Request-Headers: *");
require __DIR__.'/vendor/autoload.php';


class Kernel extends BaseKernel
{
    use MicroKernelTrait;

    /**
     * @var
     */
    private $entityManager;

    /**
     * @var
     */
    private $repository;

    /**
     * @var
     */
    private $factory;

    /**
     * @var
     */
    private $signup;

    /**
     * @var array
     */
    private static $landingPages = [
        'default' => '/loggedin'
    ];

    /**
     * @var
     */
    private $settings;

    public function __construct($environment, $debug)
    {
        parent::__construct($environment, $debug);
        require_once 'settings.php';
        $this->signup = new SignUp($settings);
        self::$landingPages['suite'] = $settings['suite']['base_url'] . '/index.php?login_token=1&module=Users&action=Login';
        self::$landingPages['mautic'] = $settings['mautic']['base_url'] . '/saml/login?login_token=1';
        $this->settings = $settings;
    }

    public function registerBundles()
    {
        return array(
            new Symfony\Bundle\FrameworkBundle\FrameworkBundle(),
            new Symfony\Bundle\TwigBundle\TwigBundle(),
            new Nelmio\CorsBundle\NelmioCorsBundle(),
            new \Symfony\Bundle\MonologBundle\MonologBundle(),
        );
    }

    protected function configureContainer(ContainerBuilder $c, LoaderInterface $loader)
    {
        // PHP equivalent of config/packages/framework.yaml
        $c->loadFromExtension('framework', array(
            'secret' => 'S0ME_SECRET',
            'templating' => ['engines' => ['twig']],
        ));

        $configValues = Yaml::parse(file_get_contents('nelmio_cors.yaml'));

        $c->loadFromExtension('nelmio_cors', $configValues['nelmio_cors']);

        $configValues1 = Yaml::parse(file_get_contents('config/config.yml'));

        $c->loadFromExtension('monolog', $configValues1['monolog']);
    }

    private function getLogger()
    {
        if (!isset($this->logger)) {
            $this->logger = $this->container->get('logger');
        }

        return $this->logger;
    }

    protected function configureRoutes(RouteCollectionBuilder $routes)
    {
        // kernel is a service that points to this class
        // optional 3rd argument is the route name
        $routes->add('/', 'Kernel::indexAction', 'index');

        $routes->add('/start', 'Kernel::startAction', 'start');

        $routes->add('/create', 'Kernel::createAction', 'create');

        $routes->add('/mautic', 'Kernel::mauticAction', 'mautic');

        $routes->add('/suite','Kernel::suiteAction', 'suite');

        $routes->add('/roles','Kernel::rolesAction', 'roles');

        $routes->addRoute(new Route('/success', array(
            '_controller' => 'Symfony\Bundle\FrameworkBundle\Controller\TemplateController::templateAction',
            'template'    => 'success.html.twig',
        )), 'success');

        /*$routes->addRoute(new Route('/loggedin', array(
            '_controller' => 'Symfony\Bundle\FrameworkBundle\Controller\TemplateController::templateAction',
            'template'    => 'loggedin.html.twig',
        )), 'loggedin');*/

        $routes->addRoute(new Route('/signup', array(
            '_controller' => 'Symfony\Bundle\FrameworkBundle\Controller\TemplateController::templateAction',
            'template'    => 'signup.html.twig',
        )), 'signup');

        $routes->add('/test','Kernel::testAction', 'test');

        $routes->add('/login','Kernel::loginAction', 'login');

        $routes->add('/loggedin','Kernel::loggedinAction', 'loggedin');

        $routes->add('/loggedout','Kernel::loggedoutAction', 'loggedout');

        $routes->add('/suitelogin','Kernel::suiteloginAction', 'suitelogin');

        $routes->add('/cookies','Kernel::cookiesAction', 'cookies');

        $routes->add('/firstloginmautic','Kernel::firstloginmauticAction', 'firstloginmautic');

        $routes->add('/getreportparam','Kernel::getreportparamAction', 'getreportparam');

        $routes->add('/suiteloginapp','Kernel::suiteloginappAction', 'suiteloginapp');

        $routes->add('/suitecreateuser','Kernel::suitecreateuserAction', 'suitecreateuser');
    }


    public function loggedinAction()
    {
        session_start();

        $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . ' session pre: ' . $_SESSION['pre_user_name']);

        if (!empty($_SESSION['pre_user_name'])){
            $_SESSION['user_name'] = $_SESSION['pre_user_name'];

            unset($_SESSION['pre_user_name']);

            $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . ' session user name: ' . $_SESSION['user_name']);

            header('Location:/login');
            exit;
        } else {

            header('Location:/start');
            exit;
        }
    }

    public function loggedoutAction()
    {
        session_start();
        $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ );
        if (isset($_SESSION['pre_user_name'])){
            unset($_SESSION['pre_user_name']);
        }

        if (isset($_SESSION['user_name'])) {
            unset($_SESSION['user_name']);
        }

        $this->removeCookiesByLogout('mautic');

        $this->removeCookiesByLogout('suite');

        // Unset all of the session variables.
        $_SESSION = array();

        // If it's desired to kill the session, also delete the session cookie.
        // Note: This will destroy the session, and not just the session data!
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }

        // Finally, destroy the session.
        session_destroy();

        $html = $this->container->get('templating')->render('loggedout.html.twig');

        return new Response($html);
    }

    private function removeCookiesByLogout($source)
    {
        $this->getLogger()->log('debug', 'source: ' . $source);

        if ($source == 'mautic') {
            $url = self::$landingPages['suite'] . '/s/logout';
        } else {
            $url =  self::$landingPages['suite'] . '/index.php?module=Users&action=Logout';
        }
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_HEADER, TRUE);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);

        $cookiesRepository = new CookiesRepository($this->settings['home_db']);

        $cookies = $cookiesRepository->getCookies($source);

        $this->getLogger()->log('debug', '$cookies: ' . print_r($cookies, true));

        $name = $cookies->getName();
        $value = $cookies->getValue();

        curl_setopt($curl, CURLOPT_HTTPHEADER, array("Cookie: $name=$value"));
        $head = curl_exec($curl);

        //$this->getLogger()->log('debug', __METHOD__ . ' $head: ' . __LINE__ . print_r($head, true));

        $httpCode = curl_getinfo($curl);
        $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . print_r($httpCode, true));
    }

    public function suiteloginAction()
    {
        session_start();

        $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__);
        if (empty($_SESSION['user_name'])) {
            $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . ' : empty session');
            header('Location:' . '/start');
            exit;
        } else {
            header($this->settings['idp']['singleSignOnService']['url']);
            exit;
        }
    }

    public function cookiesAction()
    {
        $cookiesRepository = new CookiesRepository($this->settings['home_db']);

        $cookies = $cookiesRepository->getCookies();

        var_dump($cookies); exit;
    }


    public function getreportparamAction()
    {
        session_start();

        $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__);
        if (empty($_SESSION['user_name'])) {
            $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . ' : empty session');
            header('Location:' . '/suiteloginapp');
            
            exit;
        } else {
            header($this->settings['idp']['singleSignOnService']['url']);
            exit;
        }

    }

    public function suiteloginappAction()
    {
        $this->signup->setLogger($this->getLogger());

        try {
            $sessionTokenData = $this->signup->loginApp();
        } catch (SignUpException $e) {
            $html = $this->container->get('templating')->render('index.html.twig', ['error' => 'yes']);

            return new Response($html);
        } catch (\Exception $e) {
            $html = $this->container->get('templating')->render('index.html.twig', ['error' => 'yes']);

            return new Response($html);
        }

        $sessionToken = $sessionTokenData->sessionToken;

        $this->getLogger()->log('debug', print_r($sessionTokenData, true));

        $_SESSION['pre_user_name'] = $sessionTokenData->user->email;

        $this->getLogger()->log('debug', print_r($sessionTokenData->user, true));

        $this->getLogger()->log('debug', 'session pre: ' . $_SESSION['pre_user_name']);

        $callback = self::$landingPages['reports'] . '&action=getModuleOperatorField';

        $html = $this->container->get('templating')->render(
            'cors.html.twig',
            [
                'session_token' => $sessionToken,
                'callback' => $callback,
                'url' => $this->getUrl()
            ]
        );

        return new Response($html);
    }

    private function getUrl()
    {
        $array = parse_url($this->settings['idp']['singleSignOnService']['url']);

        $url = $array['scheme'] . '://' . $array['host'];

        return $url;
    }


    public function loginAction()
    {
        session_start();

        $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__);

        //set callback by redirecting
        if (!empty($_REQUEST['callback']) && in_array($_REQUEST['callback'], array_keys(self::$landingPages))) {
            $_SESSION['callback'] = $_REQUEST['callback'];
        }

        if (empty($_SESSION['user_name'])) {
            if (empty($_SESSION['pre_user_name'])) {
                //show login form with action start
                $html = $this->container->get('templating')->render('index.html.twig', ['error' => 'no']);

                return new Response($html);
            } else {
                //set session for user_name
                $_SESSION['user_name'] = $_SESSION['pre_user_name'];
            }
        }

        if (!empty($_SESSION['pre_user_name'])) {
            unset($_SESSION['pre_user_name']);
        }

        if (!empty($_SESSION['callback'])) {
            header('Location: '. self::$landingPages[$_SESSION['callback']]);
            exit;
        } else {
            //show you are logged in as user name
            $html = $this->container->get('templating')->render(
                'loggedin.html.twig',
                [
                    'user_name' => $_SESSION['user_name'],
                    'suite_url' => $this->settings['suite']['base_url'],
                    'mautic_url'  => $this->settings['mautic']['base_url']
                ]
            );

            return new Response($html);
        }
    }

    public function rolesAction()
    {
        $this->signup->setLogger($this->getLogger());
        $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__);

        try {
            $roles = $this->signup->getOneLoginRoles();
            var_dump($roles);
        } catch (\Exception $e) {
            $this->getLogger()->log('error', __METHOD__ . ' : ' . __LINE__ . ' : ' . get_class($e) . ' : ' . $e->getMessage());
        }
    }

    public function suiteAction()
    {
        $this->signup->setLogger($this->getLogger());

        try {
            $result = $this->signup->createUserSuite();

            $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . ' : ' . print_r($result, true));

            return new JsonResponse(['success' => true]);
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
            $this->getLogger()->log('error', __METHOD__ . ' : ' . __LINE__ . ' : ' . get_class($e) . ' : ' . $e->getMessage());
            $errorData = ['error' => true, 'message' => $e->getMessage()];
            return new JsonResponse($errorData);
        }
    }

    public function indexAction()
    {
        $this->container->get('twig.loader')->addPath('templates/', $namespace = '__main__');
        $html = $this->container->get('templating')->render('index.html.twig', ['error' => 'no']);

        return new Response($html);
    }

    public function startAction()
    {
        session_start();

        if (isset($_SESSION['pre_user_name'])){
            unset($_SESSION['pre_user_name']);
        }

        if (isset($_SESSION['user_name'])) {
            unset($_SESSION['user_name']);
        }

        $this->signup->setLogger($this->getLogger());

        try {
            $sessionTokenData = $this->signup->login();
        } catch (SignUpException $e) {
            $html = $this->container->get('templating')->render('index.html.twig', ['error' => 'yes']);

            return new Response($html);
        } catch (\Exception $e) {
            $html = $this->container->get('templating')->render('index.html.twig', ['error' => 'yes']);

            return new Response($html);
        }

        $sessionToken = $sessionTokenData->sessionToken;

        $this->getLogger()->log('debug', print_r($sessionTokenData, true));

        $_SESSION['pre_user_name'] = $sessionTokenData->user->email;

        $this->getLogger()->log('debug', print_r($sessionTokenData->user, true));

        $this->getLogger()->log('debug', 'session pre: ' . $_SESSION['pre_user_name']);

        $callback = isset($_SESSION['callback']) && !empty(self::$landingPages[$_SESSION['callback']])?
            self::$landingPages[$_SESSION['callback']]: self::$landingPages['default'];

        $html = $this->container->get('templating')->render(
            'cors.html.twig',
            [
                'session_token' => $sessionToken,
                'callback' => $callback,
                'url' => $this->getUrl()
            ]);

        return new Response($html);
    }

    public function createAction()
    {
        $valid = $this->signup->getValidator()->validateParameter();

        $this->signup->setLogger($this->getLogger());

        if (!$valid) {
            $errorMessage = $this->signup->getValidator()->getErrorMessage();

            $this->getLogger()->log('error', __METHOD__ . ' : ' . __LINE__ . ' errorMessage : ' . $errorMessage);
            $errorData = ['error' => true, 'message' => $errorMessage];
            return new JsonResponse($errorData);
        }

        $parameter = [
            "email" => $_POST['email'],
            "firstname" => $_POST['firstname'],
            "lastname" => $_POST['lastname']
        ];

        try {
            $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . ' : before creating user OneLogin');
            $user = $this->signup->createUserOneLogin($parameter);
            $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . ' : user OneLogin created');
            $this->signup->setPasswordForUserOnelogin($user->id, $_POST['password']);
            $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . ' : password set for user OneLogin');

            $defaultRole = $this->signup->getOneLoginDefaultRole();

            $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . ' : default user role in OneLogin' .
                print_r($defaultRole, true));

            $resultAssigningDefaultRole = $this->signup->setDefaultRoleForUserInOnelogin($user->id, $defaultRole->getID());

            $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . ' : default role assigned to user OneLogin');
            return new JsonResponse(['success' => true]);

        } catch (SignUpException $e){

            $this->getLogger()->log('error',  __METHOD__ . ' : ' . __LINE__ . 'exception: ' . get_class($e) . ' : ' . $e->getMessage());

            $errorData = ['error' => true, 'message' => $e->getMessage()];
            return new JsonResponse($errorData);

        } catch (\Exception $e){
            $this->getLogger()->log('error',  __METHOD__ . ' : ' . __LINE__ . 'exception: ' . get_class($e) . ' : ' . $e->getMessage());

            $errorData = ['error' => true, 'message' => $e->getMessage()];
            return new JsonResponse($errorData);
        }

    }

    public function suitecreateuserAction()
    {
        $_POST = [
            'email' => 'test1@test1.com',
            'first_name' => 'Test1',
            'last_name' => 'Test1',
            'password' => 'Test12',
            'mautic_id_c' => '1234'
        ];

        $this->suiteAction();

    }

    public function firstloginmauticAction()
    {
        $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__);




        $this->mauticAction();
    }

    public function mauticAction()
    {
        session_start();

        $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__);

        try {
            $this->signup->setLogger($this->getLogger());

            $result = $this->signup->createUserMautic([
                'username' => $_POST['username'],
                'firstName' => $_POST['firstname'],
                'lastName' => $_POST['lastname'],
                'email' => $_POST['email'],
                'password' => $_POST['password'],
                'plainPassword' => $_POST['password'],
                'role' => '2',


            ]);

            $this->getLogger()->log('debug', __METHOD__ . ' : ' . __LINE__ . ' : user create in Mautic ' . print_r($result, true));

            return new JsonResponse(['success' => true, 'mautic_id_c' => $result['user']['id']]);
        } catch (\Exception $e){
            $this->getLogger()->log('error',  __METHOD__ . ' : ' . __LINE__ . 'exception: ' . get_class($e) . ' : ' . $e->getMessage());

            $this->getLogger()->log('error',  print_r($_SESSION['oauth']['debug'], true));

            $errorData = ['error' => true, 'message' => $e->getMessage()];
            return new JsonResponse($errorData);
        }
    }

    public function testAction()
    {

        /**
         *  SAML Handler
         */

        session_start();

        //require_once dirname(__DIR__).'/_toolkit_loader.php';

        require_once 'settings.php';

        $auth = new Auth($settings);

        if (isset($_GET['sso'])) {
            //$auth->login();

            # If AuthNRequest ID need to be saved in order to later validate it, do instead
             $ssoBuiltUrl = $auth->login(null, array(), false, false, true);

             //echo $ssoBuiltUrl; exit;
             $ssoBuiltUrl = 'http://microsymfony.local';

             $_SESSION['AuthNRequestID'] = $auth->getLastRequestID();
             header('Pragma: no-cache');
             header('Cache-Control: no-cache, must-revalidate');
             header('Location: ' . $ssoBuiltUrl);
             exit();

        } else if (isset($_GET['acs'])) {
            if (isset($_SESSION) && isset($_SESSION['AuthNRequestID'])) {
                $requestID = $_SESSION['AuthNRequestID'];
            } else {
                $requestID = null;
            }

            $auth->processResponse($requestID);

            $errors = $auth->getErrors();

            if (!empty($errors)) {
                echo '<p>',implode(', ', $errors),'</p>';
            }

            if (!$auth->isAuthenticated()) {
                echo "<p>Not authenticated</p>";
                exit();
            }

            $_SESSION['samlUserdata'] = $auth->getAttributes();
            $_SESSION['samlNameId'] = $auth->getNameId();
            $_SESSION['samlNameIdFormat'] = $auth->getNameIdFormat();
            $_SESSION['samlSessionIndex'] = $auth->getSessionIndex();
            unset($_SESSION['AuthNRequestID']);
            if (isset($_POST['RelayState']) && Utils::getSelfURL() != $_POST['RelayState']) {
                $auth->redirectTo($_POST['RelayState']);
            }
        } else if (isset($_GET['sls'])) {
            if (isset($_SESSION) && isset($_SESSION['LogoutRequestID'])) {
                $requestID = $_SESSION['LogoutRequestID'];
            } else {
                $requestID = null;
            }

            $auth->processSLO(false, $requestID);
            $errors = $auth->getErrors();
            if (empty($errors)) {
                echo '<p>Sucessfully logged out</p>';
            } else {
                echo '<p>', implode(', ', $errors), '</p>';
            }
        }

        if (isset($_SESSION['samlUserdata'])) {
            if (!empty($_SESSION['samlUserdata'])) {
                $attributes = $_SESSION['samlUserdata'];
                echo 'You have the following attributes:<br>';
                echo '<table><thead><th>Name</th><th>Values</th></thead><tbody>';
                foreach ($attributes as $attributeName => $attributeValues) {
                    echo '<tr><td>' . htmlentities($attributeName) . '</td><td><ul>';
                    foreach ($attributeValues as $attributeValue) {
                        echo '<li>' . htmlentities($attributeValue) . '</li>';
                    }
                    echo '</ul></td></tr>';
                }
                echo '</tbody></table>';
            } else {
                echo "<p>You don't have any attribute</p>";
            }

            echo '<p><a href="?slo" >Logout</a></p>';
        } else {
            echo '<p><a href="?sso" >Login</a></p>';
            echo '<p><a href="?sso2" >Login and access to attrs.php page</a></p>';
        }

    }


}

$kernel = new Kernel('dev', true);
$request = Request::createFromGlobals();

$response = $kernel->handle($request);
$response->send();
$kernel->terminate($request, $response);
