<?php

namespace Validation;


class Validator
{
    private $errorMessage = 'Form parameter not valid.';

    public function validateParameter()
    {
        if (!isset($_POST['email'])){
            $this->errorMessage = 'Empty email';
            return;
        }

        if (!isset($_POST['firstname'])){
            $this->errorMessage = 'Empty firstname';
            return;
        }

        if (!isset($_POST['lastname'])){
            $this->errorMessage = 'Empty lastname';
            return;
        }

        if (!isset($_POST['username'])){
            $this->errorMessage = 'Empty username';
            return;
        }

        if (!isset($_POST['password'])){
            $this->errorMessage = 'Empty password';
            return;
        }

        $emailCheck = self::validateEmail($_POST['email']);
        if (!$emailCheck) {
            $this->errorMessage = 'Invalid email';
            return;
        }
        $firstnameCheck = self::validateText($_POST['firstname']);
        $lastnameCheck = self::validateText($_POST['lastname']);
        $usernameCheck = self::validateText($_POST['username'], 5);
        $passwordCheck = self::validatePassword($_POST['password']) && self::validateText($_POST['password'], 6);

        if ($emailCheck && $firstnameCheck && $lastnameCheck && $usernameCheck && $passwordCheck) {
            return true;
        }
    }

    private static function validateEmail($value)
    {
        if (preg_match("/^(([^<>()\[\]\\.,;:\s@\"]+(\.[^<>()\[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/",
            $value))
        {
            return true;
        }
    }

    private static function validateText($value, $length = 2)
    {
        if (strlen($value) >= $length) {
            return true;
        }
    }

    private static function validatePassword($value)
    {
        if (preg_match('/[a-z]/', $value) && preg_match('/[A-Z]/', $value) && preg_match('/[0-9]/', $value)) {
            return true;
        }
    }

    /**
     * @return mixed
     */
    public function getErrorMessage()
    {
        return $this->errorMessage;
    }


}