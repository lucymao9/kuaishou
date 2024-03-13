<?php

namespace Lucymao9\Kuaishou;

use GuzzleHttp\Client;
use Lucymao9\Kuaishou\Exceptions\InvalidArgumentException;
use Lucymao9\Kuaishou\Exceptions\InvalidPublicKeyException;
use Lucymao9\Kuaishou\Exceptions\InvalidResponseException;

class Kuaishou
{
    protected $host = 'https://lbs-open.kuaishou.com';

    protected $signSecret;

    /**
     * @var mixed
     */
    protected $appSecret;
    /**
     * @var mixed
     */
    protected $appKey;
    protected $accessToken = '';
    protected $refreshToken = '';

    protected $expiresIn;

    protected $client;

    protected $currentMethod = [];


    public function __construct(array $config)
    {
        if (!isset($config['appKey'])) {
            throw new InvalidPublicKeyException("Missing Config -- [secret]");
        }
        if (!isset($config['appSecret'])) {
            throw new InvalidPublicKeyException("Missing Config -- [secret]");
        }
        if (!isset($config['signSecret'])) {
            throw new InvalidPublicKeyException("Missing Config -- [secret]");
        }

        if (isset($config['host']) && $config['host']) $this->host = $config['host'];
        $this->signSecret = $config['signSecret'];
        $this->appSecret = $config['appSecret'];
        $this->appKey = $config['appKey'];
    }

    /**
     * 获取AccessToken
     * @return mixed|string|null
     * @throws Exceptions\LocalCacheException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAccessToken(string $code)
    {
        $response = $this->getHttpClient()->get('/oauth2/access_token', [
            'query' => [
                'app_id' => $this->appKey,
                'grant_type' => 'code',
                'code' => $code,
                'app_secret' => $this->appSecret,
            ],
        ])->getBody()->getContents();
        $result = json_decode($response, true);
        if ($result['result'] != 1) {
            throw new InvalidResponseException($result['error_msg'], $result['result']);
        }
        $this->accessToken = $result['access_token'];
        $this->expiresIn = time() + $result['expires_in'];
        return [
            'access_token' => $result['access_token'],
            'refresh_token' => $result['refresh_token'],
            'open_id' => $result['open_id'],
            'expires_in' => $result['expires_in'],
            'scopes' => $result['scopes'],
        ];
    }

    public function refreshAccessToken(string $refreshToken)
    {
        $response = $this->getHttpClient()->get('/oauth2/refresh_token', [
            'query' => [
                'app_id' => $this->appKey,
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
                'app_secret' => $this->appSecret,
            ],
        ])->getBody()->getContents();
        $result = json_decode($response, true);
        if ($result['result'] != 1) {
            throw new InvalidResponseException($result['error_msg'], $result['result']);
        }
        $this->accessToken = $result['access_token'];
        $this->expiresIn = time() + $result['expires_in'];
        return [
            'access_token' => $result['access_token'],
            'expires_in' => $result['expires_in'],
            'refresh_token' => $result['refresh_token'],
            'refresh_token_expires_in' => $result['refresh_token_expires_in'],
            'scopes' => $result['scopes'],
        ];
    }

    /**
     * 设置 AccessToken
     * @param string $accessToken
     * @param int $expiresIn
     * 用户需要使用自己的缓存驱动，请求接口前必须先设置 AccessToken
     * AccessToken 有效期默认48小时，RefreshToken 有效期默认180天
     * 如 AccessToken 已过期请用 refreshAccessToken方法刷新 AccessToken，此方法也会同时刷新 RefreshToken的有效期
     * 如 RefreshToken 也过期 请在快手后台重新授权应用，会同时刷新 AccessToken 和 RefreshToken
     */
    public function setAccessToken(string $accessToken, int $expiresIn = 172800)
    {
        if (!is_string($accessToken)) {
            throw new InvalidArgumentException("Invalid AccessToken type, need string.");
        }
        $this->accessToken = $accessToken;
        $this->expiresIn = time() + $expiresIn;

    }

    /**
     * 商品券核销
     * @param array $params
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function fulfilmentVerify(array $params = [])
    {
        if (!isset($params['verify_token'])) throw new InvalidArgumentException("Missing param -- [verify_token]");
        if (!isset($params['poi_id'])) throw new InvalidArgumentException("Missing param -- [poi_id]");
        if (!isset($params['order_id'])) throw new InvalidArgumentException("Missing param -- [order_id]");
        $this->setCurrentMethod(__FUNCTION__, func_get_args());

        $json = [
            'verify_token' => $params['verify_token'],//一次验券的标识 (用于短时间内的幂等)； 平台券的verify_token由验券准备接口返回； 三方券的verify_token由开发者自生成，多次验券verify_token的值要有变化
            'poi_id' => $params['poi_id'],//核销的快手门店id
            'order_id' => $params['order_id'],//快手订单号
        ];
        //验券准备接口返回的加密快手券码
        if (isset($params['encrypted_codes']) && $params['encrypted_codes'])
            $json['encrypted_codes'] = $params['encrypted_codes'];
        //三方原始券码值列表 (encrypted_codes/codes/code_with_time_list必须三选一)
        if (isset($params['codes']) && $params['codes'])
            $json['codes'] = $params['codes'];
        //带有核销时间的三方码列表 （如果code_with_time_list 和 codes 同时传， 本字段优先级更高）
        if (isset($params['code_with_time_list']) && $params['code_with_time_list'])
            $json['code_with_time_list'] = $params['code_with_time_list'];
        //外部订单ID
        if (isset($params['out_order_id']) && $params['out_order_id'])
            $json['out_order_id'] = $params['out_order_id'];
        //快手侧的券唯一id 三方码一单一码商品用此核销，一单一码商品核销必传
        if (isset($params['certificate_ids']) && $params['certificate_ids'])
            $json['certificate_ids'] = $params['certificate_ids'];

        $result = $this->doRequest('post', '/goodlife/v1/fulfilment/certificate/verify', ['json' => $json]);
        return $result;
    }

    private function setCurrentMethod($method, $arguments = [])
    {
        $this->currentMethod = ['method' => $method, 'arguments' => $arguments];
    }

    private function getHttpClient()
    {
        if (!$this->client) {
            return new Client(['base_uri' => $this->host]);
        }
        return $this->client;
    }

    private function doRequest(string $method, $uri = '', array $options = [])
    {
        if (!$this->accessToken) throw new InvalidPublicKeyException('please set accessToken.');
        $options['headers'] = [
            'Content-type' => 'application/json',
            'access-token' => $this->accessToken
        ];
        $response = $this->getHttpClient()->request($method, $uri, $options)->getBody()->getContents();
        $result = json_decode($response, true);

        if (!$result) {
            throw new InvalidResponseException('invalid response');
        }
        $data = $result['data'];
        if ($data['error_code'] != 0) {
            $errorDescription = $data['description'];
            if (isset($data['extra'])) {
                $errorDescription = $data['description'] . ' ' . $data['sub_description'];
            }
            throw new InvalidResponseException($errorDescription, $data['error_code']);
        }
        return $result;
    }

    public function verify(string $http_body, array $url_params, string $signStr)
    {
        if (!$this->signSecret) {
            throw new InvalidPublicKeyException(" verify signature wihtout public key");
        }
        if (isset($url_params['sign'])) unset($url_params['sign']);
        ksort($url_params);
        $data = $this->signSecret . "&" . http_build_query($url_params) . "&http_body=" . $http_body;
        return $signStr == hash("sha256", $data);  //bool
    }
}