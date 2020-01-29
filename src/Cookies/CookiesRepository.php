<?php
namespace Cookies;

class CookiesRepository
{
    /**
     * @var
     */
    private $entityManager;

    public function __construct(array $connectionParams)
    {
        //test
        //$config = new \Doctrine\DBAL\Configuration();

        /*$connectionParams = array(
            'dbname' => 'ebdb',
            'user' => 'admin',
            'password' => '9R22i8am9RlvIaxPVDwA',
            'host' => 'home.ciciazhismpi.eu-central-1.rds.amazonaws.com',
            'driver' => 'pdo_mysql',
        );*/
        //$conn = \Doctrine\DBAL\DriverManager::getConnection($connectionParams, $config);

        //\Doctrine\DBAL\Types\Type::addType('uuid', 'Ramsey\Uuid\Doctrine\UuidType');

        //var_dump($conn);

        // Setup Doctrine
        $configuration = \Doctrine\ORM\Tools\Setup::createAnnotationMetadataConfiguration(
            $paths = [__DIR__ . '/Cookies'],
            $isDevMode = true
        );

        // Get the entity manager
        $this->entityManager = \Doctrine\ORM\EntityManager::create($connectionParams, $configuration);


        $connection = $this->entityManager->getConnection();
        $connection->getDatabasePlatform()->registerDoctrineTypeMapping('enum', 'string');

    }

    public function getCookies($source = 'mautic')
    {
        return $this->entityManager->getRepository('\\Cookies\\Cookies')->findOneBy(
            ['source' => $source], ['createdAt' => 'DESC']
        );
    }
}