<?php

namespace AndreiPop\Promotiful;

if (!function_exists('getallheaders')) {
    function getallheaders()
    {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }
}

class PromotifulWebhook
{
    protected $secret;
    protected $headers;
    protected $data;
    protected $is_valid_request;

    public function __construct($secret)
    {
        $this->secret = $secret;
        $this->headers = getallheaders();
        $this->is_valid_request = false;
        $this->data = null;

        $body = file_get_contents('php://input');

        if ($this->getRequestSignature() == $this->generateSHA1Signature($body, $this->secret)) {
            $this->is_valid_request = true;
            $this->data = json_decode($body, true);
        }
    }

    public function sendRequest($body, $url, $key, $remoteIp, $timestamp)
    {
        $signature = $this->generateSHA1Signature($body, $this->secret);

        $context = stream_context_create(array(
            'http' => array(
                'header'        =>
                    "Content-type: application/json" . "\r\n" .
                    "Accept: application/json" . "\r\n" .
                    "X-Key: $key\r\n" .
                    "X-Signature: $signature\r\n" .
                    "X-Remote-Ip: $remoteIp\r\n" .
                    "X-Submit-Time: $timestamp\r\n",
                'method'        => 'POST',
                'content'       => $body,
                'ignore_errors' => true,
                'timeout'       => 10
            )
        ));
        $response = file_get_contents($url, false, $context);

        return $response;
    }

    public function isValidRequest()
    {
        return $this->is_valid_request;
    }

    public function getData($key = false)
    {
        if ($key === false) {
            return ($this->is_valid_request ? $this->data : false);
        }

        if (!$this->is_valid_request || !isset($this->data[$key])) {
            return false;
        } else {
            return $this->data[$key];
        }
    }

    public function getRequestKey()
    {
        return @$this->headers['X-Key'];
    }

    public function getRequestSignature()
    {
        return @$this->headers['X-Signature'];
    }

    public function getRequestIp()
    {
        return @$this->headers['X-Remote-Ip'];
    }

    public function getRequestTimestamp()
    {
        return @$this->headers['X-Submit-Time'];
    }

    private function generateSHA1Signature($url_part, $secret_key)
    {
        return str_replace(array('+', '/', '='), array('.', '-', '_'), base64_encode(hash_hmac("sha1", $url_part, $secret_key, true)));
    }

}
