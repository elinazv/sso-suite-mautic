<?php
namespace Cookies;

use Ramsey\Uuid\UuidInterface;
use Ramsey\Uuid\Uuid;

/**
 * @Entity
 * @Table(name="cookies")
 */
class Cookies
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
     * @Column(type="string", name="name")
     */
    private $name;

    /**
     * @Column(type="string", name="value")
     */
    private $value;

    /** @Column(type="string") */
    private $source;

    /**
     * @Column(type="integer", name="created_at")
     */
    private $createdAt;

    /**
     * @return mixed
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }


}